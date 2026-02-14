;Free memory
global free_that_memory
extern VirtualFree

;BOOL VirtualFree(
;  [in] LPVOID lpAddress,
;  [in] SIZE_T dwSize,
;  [in] DWORD  dwFreeType
;)

section .text
free_that_memory:
	push rbp
	mov rbp, rsp
	sub rsp, 0x40
	mov rcx, [rbp + 16]
	mov rdx, 0
	mov r8, 0x8000
	call VirtualFree
	add rsp, 0x40
	mov rsp, rbp
	pop rbp
	ret
