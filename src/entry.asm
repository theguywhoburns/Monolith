section .
global _start
_start:
    push 0 ; exit code
    jmp platform_exit

%ifdef MONOLITH_PLATFORM_LINUX
section .text
global platform_exit

platform_exit:
%ifdef MONOLITH_ARCH_X86_64
    ; Linux/MacOS-specific exit
    mov rax, 60     ; sys_exit
    pop rdi
%ifdef MONOLITH_ARCH_X86_64
    mov eax, 60     ; sys_exit
    pop edi
%endif
    syscall
%endif

%ifdef MONOLITH_PLATFORM_MACOS
section .text
global platform_exit

platform_exit:
%ifdef MONOLITH_ARCH_X86_64
    ; Windows-specific exit
    pop rax ; Exit code
    xor rcx, rcx ; Address of exit procedure
%elifdef MONOLITH_ARCH_I386
    pop eax ; Exit code
    xor ecx, ecx ; Address of exit procedure
%endif
    int 0x2E    ; Call ZwTerminateProcess
%endif