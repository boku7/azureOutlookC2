# Compile as EXE
x86_64-w64-mingw32-gcc -m64 -mwindows azureOutlookC2.c -o azureOutlookC2.exe -masm=intel

# Compile as DLL
#x86_64-w64-mingw32-gcc azureOutlookC2_DLL.c -o azureOutlookC2_DLL.dll -shared -masm=intel

# Shellcode Compile for Dropper
#x86_64-w64-mingw32-gcc -mwindows -c azureOutlookC2.c -o azureOutlookC2.o -masm=intel -Wall -m64 -fno-asynchronous-unwind-tables -nostdlib -fno-ident -Wl,-Tlinker.ld,--no-seh

# MacOS Get Shellcode
#for x in $(objdump -d azureOutlookC2.o -x86-asm-syntax=intel | grep "^ " | cut -f1 | awk -F: '{print $2}'); do echo -n "\x"$x; done; echo
# Linux Get Shellcode
#for x in $(objdump -d azureOutlookC2.o -M intel | grep "^ " | cut -f1 | awk -F: '{print $2}'); do echo -n "\x"$x; done; echo

# Copy-Paste Shellcode into dropper.c

# Compile Dropper Command
#x86_64-w64-mingw32-gcc -m64 -mwindows dropper.c -o dropper.exe -masm=intel
