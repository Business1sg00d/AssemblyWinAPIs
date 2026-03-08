global main
;extern get_some_memory
;extern GetStartupInfoW
;extern CreateProcessA
;extern ExitProcess


;word == 2 bytes
;dword == 4 bytes
;qword == 8 bytes
;LPBYTE == 8 bytes. Its a pointer.

;What is the PEB and how to access it in assembly for windows? The GS register contains the Thread Environment Block.

;Get PEB > Get Loaded Modules > Find kernel32 > Parse the export table > Load the function address.

section .text
main:
	sub rsp, 0x188			;not sure why I have to add 0x28. Seems counter-intuitive as the stack should be 0x10 aligned.
	
	;Get the PEB at gs:[0x60]
	mov rax, gs:[0x60]		;PEB location.

	;Get the Loaded Modules via the Loader Data Table (LDR).
	mov qword rbx, [rax + 0x18]

	;Get the inMemoryOrderModuleList structure.
	mov qword r12, [rbx + 0x20]

	;Get the inLoadOrderModuleList Structure.
	mov qword r13, [rbx + 0x10]

	;Get kernel32 base here? Why this weird offset? It doesn't match what I find online. But whatever.
	mov qword r14, [r12 + 0x5a0]

	;0x3c should be where we find the offset to the PE structure.
	mov rax, r14
	add rax, 0x3c
	xor rdi, rdi
	mov dil, [rax]			;byte loaded offset stored in rdi.

	;Get a pointer to kernel32 PE structure.
	xor rax, rax
	mov rax, r14
	add al, dil
	mov qword r15, rax		;pointer to PE struct in kernel32.

	;Now we need the Optional Header structure as a pointer.
	add rax, 0x18			;optional header should be 0x18 away from PE.

	;The Export Directory Table offset inside the kernel32 image.
	add rax, 0x70			;per microsoft, the export table offset (RVA) should be 0x70 away from our optional header.

	;Pointer to the Export Directory Table.
	xor rdi, rdi
	mov edi, [rax]			;should be the offset that is added to the image base. This will be the pointer to functions.
	xor rax, rax
	mov rax, r14
	add rax, rdi
	xor r12, r12
	mov qword r12, rax

	;Get the functions table pointer offset in the Export Directory Table.
	add rax, 0x1c
	xor rdi, rdi
	mov edi, [rax]

	;Pointer to the Export Address Table.
	xor rax, rax
	mov rax, r14
	add rax, rdi
	mov qword r15, rax

	;Pointer to the Ordinal Table RVA.
	xor rax, rax
	xor rdi, rdi
	mov rax, r12
	add rax, 0x24
	mov edi, [rax]
	xor rax, rax
	mov rax, r14
	add rax, rdi
	xor r13, r13
	mov qword r13, rax

	;Pointer to the Name Table RVA.
	xor rax, rax
	xor rdi, rdi
	xor rbx, rbx
	mov rax, r12
	add rax, 0x20
	mov edi, [rax]
	xor rax, rax
	mov rax, r14
	add rax, rdi
	mov qword rbx, rax

	;The ordinal base. A constant.
	xor rax, rax
	xor rdi, rdi
	mov rax, r12
	add rax, 0x10
	mov dil, [rax]

	;Say I have a loop. Prior to the loop I have a counter that starts at 0.
	;Going into the loop the first thing I do is grab the RVA of the first entry in the name table. 
	;I add this RVA to my image base, then look up the string. I compare this string to the function I'm looking for. 
	;If not found, I increment the counter then start at the begining of my loop. 
	;Once I find the matching string, I look into the ordinal table using the counter as an index. 
	;Lets say its 7. I take the ordinal at index 7, then look into the EAT using the ordinal index. 
	;This should contain the RVA that I add to my image base which is a pointer to the 
	;begining of the function I am looking for.

	;RBX == Name Table.
	;R12 == Export Directory Table.
	;R14 == Image Base of kernel32.
	;R13 == Ordinal Table pointer.

	;Initializing the counter.
	xor rdx, rdx

	
	;Initializing the function that I want, placing the string on the stack.
	xor rax, rax
	mov rax, 0x61657243 
	mov [rsp + 0x100], rax
	mov rax, 0x72506574 
	mov [rsp + 0x104], rax
	mov rax, 0x7365636f 
	mov [rsp + 0x108], rax
	mov rax, 0x00004173
	mov [rsp + 0x10c], rax
	jmp FindName


	;Begin loop.
FindName:
	xor rdi, rdi
	xor rsi, rsi
	xor rax, rax
	xor rcx, rcx
	mov rax, rbx
	lea rax, [rax + rdx*4]
	mov edi, [rax]
	xor rax, rax
	mov rax, r14
	add rax, rdi
	mov rsi, rax
	lea rdi, [rsp + 0x100]
	mov rcx, 0x0c
	repe cmpsb
	jz endme
	inc rdx
	jmp FindName

endme:
	xor rax, rax
	xor rax, rax
	xor rax, rax



	;Getting offset to ExitProcess.


	;jmp endit

	;Set up the PROCESS_INFORMATION struct.
	;------------------------------------
	;typedef struct _PROCESS_INFORMATION {
	;  HANDLE hProcess;
	;  HANDLE hThread;
	;  DWORD  dwProcessId;
	;  DWORD  dwThreadId;
	;} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
;	lea r13, [rsp + 0x88]			;pointer to PROCESS_INFORMATION struct data.
;
;
;	;Set up the STARTUPINFOA Struct.
;	;------------------------------------
;	;typedef struct _STARTUPINFOA {
;	;  DWORD  cb;
;	;  LPSTR  lpReserved;
;	;  LPSTR  lpDesktop;
;	;  LPSTR  lpTitle;
;	;  DWORD  dwX;
;	;  DWORD  dwY;
;	;  DWORD  dwXSize;
;	;  DWORD  dwYSize;
;	;  DWORD  dwXCountChars;
;	;  DWORD  dwYCountChars;
;	;  DWORD  dwFillAttribute;
;	;  DWORD  dwFlags;
;	;  WORD   wShowWindow;
;	;  WORD   cbReserved2;
;	;  LPBYTE lpReserved2;
;	;  HANDLE hStdInput;
;	;  HANDLE hStdOutput;
;	;  HANDLE hStdError;
;	;} STARTUPINFOA, *LPSTARTUPINFOA;
;	;lea r14, [rsp + 0xa8]		;figure out why the stack is treated differently than the heap.
;	mov qword rcx, 0x68
;	call get_some_memory
;	mov r12, rax
;	mov rcx, r12
;	call GetStartupInfoW
;
;
;	;Call CreateProcess WinAPI with arguments.
;	;------------------------------------
;	;BOOL CreateProcessA(
;	;  [in, optional]      LPCSTR                lpApplicationName,
;	;  [in, out, optional] LPSTR                 lpCommandLine,
;	;  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
;	;  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
;	;  [in]                BOOL                  bInheritHandles,
;	;  [in]                DWORD                 dwCreationFlags,
;	;  [in, optional]      LPVOID                lpEnvironment,
;	;  [in, optional]      LPCSTR                lpCurrentDirectory,
;	;  [in]                LPSTARTUPINFOA        lpStartupInfo,
;	;  [out]               LPPROCESS_INFORMATION lpProcessInformation
;	;);
;	;433a5c57696e646f77735c53797374656d33325c63616c632e6578655c30	<- Null terminated "C:\\Windows\\System32\\calc.exe".
;	;6578652e636c61635c32336d65747379535c73776f646e69575c3a43	<- Little endian w/o null termination.
;	mov rax, 0x575c3a43
;	mov [rsp + 0x50], rax
;	mov rax, 0x6f646e69
;	mov [rsp + 0x54], rax
;	mov rax, 0x535c7377
;	mov [rsp + 0x58], rax
;	mov rax, 0x65747379
;	mov [rsp + 0x5c], rax
;	mov rax, 0x5c32336d
;	mov [rsp + 0x60], rax
;	mov rax, 0x636c6163
;	mov [rsp + 0x64], rax
;	mov rax, 0x6578652e
;	mov [rsp + 0x68], rax
;	xor rcx, rcx
;	lea rdx, [rsp + 0x50]
;	xor r8, r8
;	xor r9, r9
;	mov qword [rsp + 0x20], 0x0000000000000000
;	mov qword [rsp + 0x28], 0x0000000000000000
;	mov qword [rsp + 0x30], 0x0000000000000000
;	mov qword [rsp + 0x38], 0x0000000000000000
;	mov qword [rsp + 0x40], r12
;	mov qword [rsp + 0x48], r13
;	call CreateProcessA
;
;	;Free memory
;	;------------------------------------
;

;endit:
;	;Exit process
;	;------------------------------------
;	xor ecx, ecx
;	call ExitProcess
