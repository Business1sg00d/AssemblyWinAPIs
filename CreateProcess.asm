global main

;word == 2 bytes
;dword == 4 bytes
;qword == 8 bytes
;LPBYTE == 8 bytes. Its a pointer.

;What is the PEB and how to access it in assembly for windows? The GS register contains the Thread Environment Block.

;Get PEB > Get Loaded Modules > Find kernel32 > Parse the export table > Load the function address.

section .text
main:
	sub rsp, 0x308			;not sure why I have to add 0x28. Seems counter-intuitive as the stack should be 0x10 aligned.
	
	;Get the PEB at gs:[0x60]
	mov rax, gs:[0x60]		;PEB location.

	;Get the Loaded Modules via the Loader Data Table (LDR).
	mov qword rbx, [rax + 0x18]

	;Get the inMemoryOrderModuleList structure.
	mov qword r12, [rbx + 0x20]

	;Looking for kernel32 base.
	mov qword rax, [r12]
	mov qword rax, [rax]
	mov qword r14, [rax + 0x20]

	;0x3c should be where we find the offset to the PE structure.
	mov rax, r14
	add rax, 0x3c
	movzx rdi, byte [rax]		;byte loaded offset stored in rdi.

	;Get a pointer to kernel32 PE structure.
	mov qword rax, r14
	add al, dil
	mov qword r15, rax		;pointer to PE struct in kernel32.

	;Now we need the Optional Header structure as a pointer.
	add rax, 0x18			;optional header should be 0x18 away from PE.

	;The Export Directory Table offset inside the kernel32 image.
	add rax, 0x70			;per microsoft, the export table offset (RVA) should be 0x70 away from our optional header.

	;Pointer to the Export Directory Table.
	mov edi, dword [rax]		;should be offset thats added to the image base; pointer directory table.
	mov qword rax, r14
	add rax, rdi
	mov qword r12, rax

	;Get the functions table pointer offset in the Export Directory Table.
	add rax, 0x1c
	mov edi, [rax]

	;Pointer to the Export Address Table.
	mov qword rax, r14
	add rax, rdi
	mov qword r15, rax

	;Pointer to the Ordinal Table RVA.
	mov qword rax, r12
	add rax, 0x24
	mov edi, [rax]
	mov qword rax, r14
	add rax, rdi
	mov qword r13, rax

	;Pointer to the Name Table RVA.
	mov qword rax, r12
	add rax, 0x20
	mov edi, [rax]
	mov qword rax, r14
	add rax, rdi
	mov qword rbx, rax

	;The ordinal base. A constant.
	mov qword rax, r12
	add rax, 0x10
	movzx rdi, byte [rax]

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
	;R13 == Ordinal Table pointer.
	;R14 == Image Base of kernel32.
	;R15 == Export Address Table (EAT).

	;Initializing the counter.
	xor rdx, rdx
	
	;Initializing the CreateProcess string to find it in the export table for kernel32.
	mov eax, 0x61657243 
	mov [rsp + 0x100], rax
	mov eax, 0x72506574 
	mov [rsp + 0x104], rax
	mov eax, 0x7365636f 
	mov [rsp + 0x108], rax
	mov eax, 0x00004173
	mov [rsp + 0x10c], rax
	xor rax, rax
	jmp keepCount

	;Count the size of the string.
keepCount:
	lea rdi, [rsp + 0x100]
	cmp byte [rdi + rax], 0x00
	je initCount
	inc rax
	jmp keepCount

	;Initialize size of string into a register.
initCount:
	mov qword [rsp + 0x20], rax
	jmp FindName

	;Begin loop.
FindName:
	mov qword rax, rbx
	lea rax, [rax + rdx*4]
	mov edi, [rax]
	mov qword rax, r14
	add rax, rdi
	mov rsi, rax
	lea rdi, [rsp + 0x100]
	mov qword rcx, [rsp + 0x20]			;Size of string.
	repe cmpsb
	jnz inca
	jmp contn

inca:
	inc rdx
	jmp FindName

contn:
	movzx rax, word [r13 + rdx*2]		;points to the index into EAT that points to RVA for CreateProcessA.
	mov edi, [r15 + rax*4]			;should be the RVA for CreateProcessA.
	lea rsi, [r14 + rdi]			;Is this a function pointer?
	mov rax, [rsp + 0x150]
	test rax, rax				;will be 0x01 if data exists here.
	jz initProcA
	mov rax, [rsp + 0x158]
	test rax, rax
	jz initSI
	mov rax, [rsp + 0x160]
	test rax, rax
	jz initEP
	mov rax, [rsp + 0x168]
	test rax, rax
	jz initVA
	mov rax, [rsp + 0x170]
	test rax, rax
	jz initPM
	mov rax, [rsp + 0x178]
	test rax, rax
	jz initTC
	mov rax, [rsp + 0x180]
	test rax, rax
	jz initST
	mov rax, [rsp + 0x188]
	test rax, rax
	jz initRT

initProcA:
	mov qword rax, rsi
	mov [rsp + 0x150], rax			;CreateProcessA on the stack via pointer.
	jmp FindSI

initSI:
	mov qword rax, rsi
	mov [rsp + 0x158], rax			;GetStartupInfoW on the stack via pointer.
	jmp callSI

initEP:
	xor rdx, rdx
	mov qword rax, rsi
	mov [rsp + 0x160], rax			;ExitProcess on the stack via pointer.
	jmp FindVA

initVA:
	xor rdx, rdx
	mov qword rax, rsi
	mov [rsp + 0x168], rax			;VirtualAllocEX on the stack via pointer.
	jmp FindPM

initPM:
	xor rdx, rdx
	mov qword rax, rsi
	mov [rsp + 0x170], rax			;WriteProcessMemory on the stack via pointer.
	jmp FindTC

initTC:
	xor rdx, rdx
	mov qword rax, rsi
	mov [rsp + 0x178], rax			;GetThreadContext on the stack via pointer.
	jmp FindST

initST:
	xor rdx, rdx
	mov qword rax, rsi
	mov [rsp + 0x180], rax			;SetThreadContext on the stack via pointer.
	jmp FindRT

initRT:
	xor rdx, rdx
	mov qword rax, rsi
	mov [rsp + 0x188], rax			;ResumeThread on the stack via pointer.
	jmp CrtPrc


	;Now find GetStartupInfoW.
	;Set up the STARTUPINFOA Struct.
	;------------------------------------
	;typedef struct _STARTUPINFOA {
	;  DWORD  cb;
	;  LPSTR  lpReserved;
	;  LPSTR  lpDesktop;
	;  LPSTR  lpTitle;
	;  DWORD  dwX;
	;  DWORD  dwY;
	;  DWORD  dwXSize;
	;  DWORD  dwYSize;
	;  DWORD  dwXCountChars;
	;  DWORD  dwYCountChars;
	;  DWORD  dwFillAttribute;
	;  DWORD  dwFlags;
	;  WORD   wShowWindow;
	;  WORD   cbReserved2;
	;  LPBYTE lpReserved2;
	;  HANDLE hStdInput;
	;  HANDLE hStdOutput;
	;  HANDLE hStdError;
	;} STARTUPINFOA, *LPSTARTUPINFOA;

	;VOID GetStartupInfoW(
	;  [out] LPSTARTUPINFOW lpStartupInfo
	;);

FindSI:
	mov eax, 0x53746547 
	mov [rsp + 0x100], rax
	mov eax, 0x74726174 
	mov [rsp + 0x104], rax
	mov eax, 0x6e497075 
	mov [rsp + 0x108], rax
	mov eax, 0x00576f66
	mov [rsp + 0x10c], rax
	xor rax, rax
	jmp keepCount

	;Call GetStartupinfoW.
callSI:
	lea qword rcx, [rsp + 0x200]
	mov rax, [rsp + 0x158]
	call rax
	jmp FindEP

	;Find ExitProcess.
FindEP:
	mov eax, 0x74697845 
	mov [rsp + 0x100], rax
	mov eax, 0x636f7250 
	mov [rsp + 0x104], rax
	mov eax, 0x00737365
	mov [rsp + 0x108], rax
	xor rax, rax
	xor rdx, rdx
	jmp keepCount

	;Find VirtualAlloc.
FindVA:
	mov eax, 0x74726956 
	mov [rsp + 0x100], rax
	mov eax, 0x416c6175 
	mov [rsp + 0x104], rax
	mov eax, 0x636f6c6c
	mov [rsp + 0x108], rax
	mov eax, 0x00007845
	mov [rsp + 0x10c], rax
	xor rax, rax
	jmp keepCount

	;Find WriteProcessMemory.
FindPM:
	mov eax, 0x74697257 
	mov [rsp + 0x100], rax
	mov eax, 0x6f725065 
	mov [rsp + 0x104], rax
	mov eax, 0x73736563 
	mov [rsp + 0x108], rax
	mov eax, 0x6f6d654d 
	mov [rsp + 0x10c], rax
	mov eax, 0x00007972
	mov [rsp + 0x110], rax
	xor rax, rax
	jmp keepCount

	;Find GetThreadContext.
FindTC:
	mov eax, 0x54746547 
	mov [rsp + 0x100], rax
	mov eax, 0x61657268 
	mov [rsp + 0x104], rax
	mov eax, 0x6e6f4364 
	mov [rsp + 0x108], rax
	mov eax, 0x74786574
	mov [rsp + 0x10c], rax
	xor rax, rax
	jmp keepCount

FindST:
	mov eax, 0x54746553 
	mov [rsp + 0x100], rax
	mov eax, 0x61657268 
	mov [rsp + 0x104], rax
	mov eax, 0x6e6f4364 
	mov [rsp + 0x108], rax
	mov eax, 0x74786574
	mov [rsp + 0x10c], rax
	xor rax, rax
	jmp keepCount

FindRT:
	mov eax, 0x75736552 
	mov [rsp + 0x100], rax
	mov eax, 0x6854656d 
	mov [rsp + 0x104], rax
	mov eax, 0x64616572
	mov [rsp + 0x108], rax
	xor rax, rax
	jmp keepCount




	;Call CreateProcess WinAPI with arguments.
CrtPrc:
	;------------------------------------
	;typedef struct _PROCESS_INFORMATION {
	;  HANDLE hProcess;
	;  HANDLE hThread;
	;  DWORD  dwProcessId;
	;  DWORD  dwThreadId;
	;} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

	;BOOL CreateProcessA(
	;  [in, optional]      LPCSTR                lpApplicationName,
	;  [in, out, optional] LPSTR                 lpCommandLine,
	;  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
	;  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
	;  [in]                BOOL                  bInheritHandles,
	;  [in]                DWORD                 dwCreationFlags,
	;  [in, optional]      LPVOID                lpEnvironment,
	;  [in, optional]      LPCSTR                lpCurrentDirectory,
	;  [in]                LPSTARTUPINFOA        lpStartupInfo,
	;  [out]               LPPROCESS_INFORMATION lpProcessInformation
	;);

	;433a5c57696e646f77735c53797374656d33325c63616c632e6578655c30	<- Null terminated "C:\\Windows\\System32\\calc.exe".
	;6578652e636c61635c32336d65747379535c73776f646e69575c3a43	<- Little endian w/o null termination.
	mov rax, 0x575c3a43
	mov [rsp + 0x50], rax
	mov rax, 0x6f646e69
	mov [rsp + 0x54], rax
	mov rax, 0x535c7377
	mov [rsp + 0x58], rax
	mov rax, 0x65747379
	mov [rsp + 0x5c], rax
	mov rax, 0x5c32336d
	mov [rsp + 0x60], rax
	mov rax, 0x636c6163
	mov [rsp + 0x64], rax
	mov rax, 0x6578652e
	mov [rsp + 0x68], rax
	xor rcx, rcx
	lea rdx, [rsp + 0x50]
	xor r8, r8
	xor r9, r9
	mov qword [rsp + 0x20], 0x0000000000000001
	mov qword [rsp + 0x28], 0x0000000000000004
	mov qword [rsp + 0x30], 0x0000000000000000
	mov qword [rsp + 0x38], 0x0000000000000000
	lea qword rax, [rsp + 0x200]
	mov qword [rsp + 0x40], rax
	lea qword rax, [rsp + 0x26c]
	mov qword [rsp + 0x48], rax
	mov qword rax, [rsp + 0x150]
	call rax
	

	;Get memory in target process
	;------------------------------------
	;[rsp + 0x150]			CreateProcessA on the stack via pointer.
	;[rsp + 0x158]			GetStartupInfoW on the stack via pointer.
	;[rsp + 0x160]			ExitProcess on the stack via pointer.
	;[rsp + 0x168]			VirtualAllocEX on the stack via pointer.
	;[rsp + 0x170]			WriteProcessMemory on the stack via pointer.
	;[rsp + 0x178]			GetThreadContext on the stack via pointer.
	;[rsp + 0x180]			SetThreadContext on the stack via pointer.
	;[rsp + 0x188]			ResumeThread on the stack via pointer.
	;[rsp + 0x26c]			PROCESS_INFORMATION struct for suspended process.

	;LPVOID VirtualAllocEx(
	;  [in]           HANDLE hProcess,
	;  [in, optional] LPVOID lpAddress,
	;  [in]           SIZE_T dwSize,
	;  [in]           DWORD  flAllocationType,
	;  [in]           DWORD  flProtect
	;);
	lea qword rax, [rsp + 0x26c]
	mov qword rcx, [rax]
	xor rdx, rdx
	mov r8d, 0x1000
	mov r9d, 0x1000
	or r9, 0x2000
	mov qword [rsp + 0x20], 0x40
	lea qword rax, [rsp + 0x168]
	mov rax, [rax]
	call rax

endit:
	;Exit process
	;------------------------------------
	xor ecx, ecx
	mov qword rax, [rsp + 0x160]
	call rax
