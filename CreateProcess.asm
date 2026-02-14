global main
extern CreateProcessA
extern ExitProcess
extern get_some_memory
extern free_that_memory

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

;word == 2 bytes
;dword == 4 bytes
;qword == 8 bytes
;LPBYTE == 8 bytes. Its a pointer.


;------------------------------------


;typedef struct _PROCESS_INFORMATION {
;  HANDLE hProcess;
;  HANDLE hThread;
;  DWORD  dwProcessId;
;  DWORD  dwThreadId;
;} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;


;------------------------------------


section .text
main:
	sub rsp, 68h   


	;Set up the STARTUPINFOA Struct.
	;------------------------------------
	push 64
	call get_some_memory
	mov r12, rax			;my base pointer table.
	mov rax, 68
	push rax
	call get_some_memory
	mov qword [r12 + 0x00], rax	;saved pointer for the struct.
	mov r13, [r12 + 0x00]		;Actual struct pointer. Use this for populating struct data for STARTUPINFOA.
	mov dword [r13], 0x6000		;cb field in the STARTUPINFO struct.
	push 1
	call get_some_memory
	mov qword [r12 + 0x08], rax	;saved pointer to lpReserved.
	mov qword [r13 + 0x04], rax	;lpReserved field pointer in the STARTUPINFO struct.
	push 1
	call get_some_memory
	mov qword [r12 + 0x10], rax	;saved pointer to lpDesktop.
	mov qword [r13 + 0x0c], rax	;lpDesktop field pointer in the STARTUPINFO struct.
	push 1
	call get_some_memory
	mov qword [r12 + 0x18], rax	;saved pointer to lpTitle.
	mov qword [r13 + 0x14], rax	;lpTitle field pointer in the STARTUPINFO struct.
	;skipping 36 bytes because I think this space is arbitrarily handled by windows OS. See below.
	push 1
	call get_some_memory
	mov qword [r12 + 0x20], rax	;saved pointer to LBBYTE member.
	mov qword [r13 + 0x3c], rax	;0x1c + 36 bytes should be offset to LBBYTE member == 0x3c.
	;leave HANDLE type empty? Windows automatically populates this?


	;Set up the PROCESS_INFORMATION struct.
	;------------------------------------
	push 24
	call get_some_memory
	mov qword [r12 + 0x28], rax	;saved pointer to the pointer to PROCESS_INFORMATION struct data.
	mov r14, rax			;pointer to PROCESS_INFORMATION struct data.


	;Call CreateProcess WinAPI with arguments.
	;------------------------------------
	push 32
	call get_some_memory
	mov qword [r12 + 0x30], rax	;string pointer being passed to CreateProcessA.
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
	mov qword [rsp + 0x28], 0x0000000000000008
	mov qword [rsp + 0x30], 0x0000000000000000
	mov qword [rsp + 0x38], 0x0000000000000000
	mov qword [rsp + 0x40], r13
	mov qword [rsp + 0x48], r14
	call CreateProcessA


	;free memory backwards.
	push qword [r12 + 0x28]
	call free_that_memory
	push qword [r12 + 0x20]
	call free_that_memory
	push qword [r12 + 0x18]
	call free_that_memory
	push qword [r12 + 0x10]
	call free_that_memory
	push qword [r12 + 0x08]
	call free_that_memory
	push r13
	call free_that_memory
	push r12
	call free_that_memory
	xor ecx, ecx
	call ExitProcess
