extern GetStartupInfoW

;VOID GetStartupInfoW(
;  [out] LPSTARTUPINFOW lpStartupInfo
;);

section .text
main:
	push rbp
	mov rbp, rsp
	sub rsp, 0x28
	mov rcx, [rbp + 0x10]
	call GetStartupInfoW
	add rsp, 0x28
	mov rsp, rbp
	pop rbp
	ret
