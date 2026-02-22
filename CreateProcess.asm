global main
extern GetStartupInfoW
extern CreateProcessA
extern ExitProcess
extern get_some_memory
extern free_that_memory


;word == 2 bytes
;dword == 4 bytes
;qword == 8 bytes
;LPBYTE == 8 bytes. Its a pointer.


section .text
main:
	sub rsp, 0x28			;not sure why I have to add 0x28. Seems counter-intuitive as the stack should be 0x10 aligned.


	;Set up the pointer table.
	;------------------------------------
	mov ecx, 0x40
	call get_some_memory
	mov r12, rax			;my base pointer table.


	;Set up the PROCESS_INFORMATION struct.
	;------------------------------------
	;typedef struct _PROCESS_INFORMATION {
	;  HANDLE hProcess;
	;  HANDLE hThread;
	;  DWORD  dwProcessId;
	;  DWORD  dwThreadId;
	;} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
	mov ecx, 0x100
	call get_some_memory
	mov qword [r12 + 0x00], rax	;saved pointer to the pointer to PROCESS_INFORMATION struct data.
	mov r13, rax			;pointer to PROCESS_INFORMATION struct data.


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
	mov ecx, 0x40
	call get_some_memory
	mov qword [r12 + 0x08], rax	;pointer to STARTUPINFO struct pointer.
	mov rcx, rax
	mov r14, rax
	call GetStartupInfoW
	;mov rax, [r12 + 0x30]


	;Call CreateProcess WinAPI with arguments.
	;------------------------------------
	mov ecx, 0x30
	call get_some_memory
	mov qword [r12 + 0x10], rax	;string pointer being passed to CreateProcessA.
	;433a5c57696e646f77735c53797374656d33325c63616c632e6578655c30	<- Null terminated "C:\\Windows\\System32\\calc.exe".
	;6578652e636c61635c32336d65747379535c73776f646e69575c3a43	<- Little endian w/o null termination.
	mov dword [rax + 0x00], 0x575c3a43
	mov dword [rax + 0x04], 0x6f646e69
	mov dword [rax + 0x08], 0x535c7377
	mov dword [rax + 0x0c], 0x65747379
	mov dword [rax + 0x10], 0x5c32336d
	mov dword [rax + 0x14], 0x636c6163
	mov dword [rax + 0x18], 0x6578652e
	xor rcx, rcx
	mov rdx, rax
	xor r8, r8
	xor r9, r9
	mov qword [rsp + 0x20], 0x0000000000000001
	mov qword [rsp + 0x28], 0x0000000000000010
	mov qword [rsp + 0x30], 0x0000000000000000
	mov qword [rsp + 0x38], 0x0000000000000000
	mov qword [rsp + 0x40], r14
	mov qword [rsp + 0x48], r13
	call CreateProcessA


	;Prepare to free memory and exit process.
	;------------------------------------
	mov rbx, r12		;save the original table pointer.
	jmp freeup


	;Free memory.
	;------------------------------------
freeup:
	mov rax, [r12]
	test rax, rax
	jz theend
	mov rcx, rax
	call free_that_memory
	add r12, 0x08
	jmp freeup


	;Exit process.
	;------------------------------------
theend:
	mov rcx, rbx		;free the original table pointer.
	call free_that_memory
	xor ecx, ecx
	call ExitProcess
