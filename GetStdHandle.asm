global main
extern GetStdHandle

;HANDLE WINAPI GetStdHandle(
;	_In_ DWROD nStdHandle
;);

;STD_INPUT_HANDLE = (DWORD) - 10. Internally, WinAPI takes this signed integer and casts it to unsigned. This is 4294967286.
;STD_OUTPUT_HANDLE = (DWORD) - 11. Internally, WinAPI takes this signed integer and casts it to unsigned. This is 4294967285.
;STD_ERROR_HANDLE = (DWORD) - 12. Internally, WinAPI takes this signed integer and cats it to unsigned. This is 4294967284.

;section .text
;get_handles:
;	push rbp
;	mov rbp, rsp
;	sub rsp, 0x40
;	mov rcx, 4294967285
;	call GetStdHandle
;	add rsp, 0x40
;	mov rsp, rbp
;	pop rbp
;	ret

section .text
main:
	sub rsp, 0x20
	mov dword rcx, 4294967285
	call GetStdHandle
	
