nasm -f win64 CreateProcess.asm -o CreateProcess.obj && \
#nasm -f win64 free_that_memory.asm -o free_that_memory.obj && \
#nasm -f win64 get_some_memory.asm -o get_some_memory.obj && \
#nasm -f win64 WinAPI_CreateProcess.asm -o WinAPI_CreateProcess.obj && \
#nasm -f win64 GetStartupInfoW.asm -o GetStartupInfoW.obj && \

x86_64-w64-mingw32-ld -e main -subsystem windows CreateProcess.obj -o CreateProcess.exe && sudo cp CreateProcess.exe /home/jackd/Documents/mountme

#x86_64-w64-mingw32-ld -e main -subsystem windows GetStartupInfoW.obj WinAPI_CreateProcess.obj CreateProcess.obj free_that_memory.obj get_some_memory.obj -o CreateProcess.exe -L /usr/x86_64-w64-mingw32/lib -luser32 -lkernel32 && sudo cp CreateProcess.exe /home/jackd/Documents/mountme
