extern CreateProcessA

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

section .text
main:
	push rbp
	mov rbp, rsp
	sub rsp, 0x40

	add rsp, 0x40
	mov rsp, rbp
	pop rbp
	ret
