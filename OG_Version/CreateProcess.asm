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

	;Get kernel32 here?
	mov qword r14, [r12 + 0x5a0]
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
