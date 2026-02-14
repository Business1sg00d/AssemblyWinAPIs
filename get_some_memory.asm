;Acquire memory.
global get_some_memory
extern VirtualAlloc

;LPVOID VirtualAlloc(
;  [in, optional] LPVOID lpAddress,
;  [in]           SIZE_T dwSize,
;  [in]           DWORD  flAllocationType,
;  [in]           DWORD  flProtect
;)

section .text
get_some_memory:
	push rbp
	mov rbp, rsp
	sub rsp, 0x40
	mov rcx, 0
	mov rdx, [rbp + 16]
	mov r8, 0x3000
	mov r9, 0x04
	call VirtualAlloc
	add rsp, 0x40
	mov rsp, rbp
	pop rbp
	ret
