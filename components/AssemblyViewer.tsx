
import React from 'react';
import { Architecture, ExploitType } from '../types';
import { Cpu } from 'lucide-react';

interface AssemblyViewerProps {
  type: ExploitType;
  arch: Architecture;
  stepId: number;
}

// Map Step IDs to line numbers (1-based index for display) in the assembly code
const STACK_STEP_MAPPING = {
  0: { [Architecture.X86]: 3, [Architecture.X64]: 3, [Architecture.ARM]: 3, [Architecture.MIPS]: 3 }, 
  1: { [Architecture.X86]: 7, [Architecture.X64]: 6, [Architecture.ARM]: 5, [Architecture.MIPS]: 5 }, 
  2: { [Architecture.X86]: 7, [Architecture.X64]: 6, [Architecture.ARM]: 5, [Architecture.MIPS]: 5 }, 
  3: { [Architecture.X86]: 7, [Architecture.X64]: 6, [Architecture.ARM]: 5, [Architecture.MIPS]: 5 }, 
  4: { [Architecture.X86]: 7, [Architecture.X64]: 6, [Architecture.ARM]: 5, [Architecture.MIPS]: 5 }, 
  5: { [Architecture.X86]: 9, [Architecture.X64]: 8, [Architecture.ARM]: 7, [Architecture.MIPS]: 10 }, 
};

const HEAP_STEP_MAPPING = {
  0: { [Architecture.X86]: 5, [Architecture.X64]: 5, [Architecture.ARM]: 5, [Architecture.MIPS]: 5 },
  1: { [Architecture.X86]: 9, [Architecture.X64]: 9, [Architecture.ARM]: 9, [Architecture.MIPS]: 9 },
  2: { [Architecture.X86]: 9, [Architecture.X64]: 9, [Architecture.ARM]: 9, [Architecture.MIPS]: 9 },
  3: { [Architecture.X86]: 9, [Architecture.X64]: 9, [Architecture.ARM]: 9, [Architecture.MIPS]: 9 },
  4: { [Architecture.X86]: 11, [Architecture.X64]: 11, [Architecture.ARM]: 11, [Architecture.MIPS]: 11 },
};

const UAF_STEP_MAPPING = {
  0: { [Architecture.X86]: 3, [Architecture.X64]: 3, [Architecture.ARM]: 3, [Architecture.MIPS]: 3 }, // Malloc A
  1: { [Architecture.X86]: 5, [Architecture.X64]: 5, [Architecture.ARM]: 5, [Architecture.MIPS]: 5 }, // Free A
  2: { [Architecture.X86]: 7, [Architecture.X64]: 7, [Architecture.ARM]: 7, [Architecture.MIPS]: 7 }, // Malloc B
  3: { [Architecture.X86]: 9, [Architecture.X64]: 9, [Architecture.ARM]: 9, [Architecture.MIPS]: 9 }, // Use Ptr1
};

const FMT_STEP_MAPPING = {
  0: { [Architecture.X86]: 3, [Architecture.X64]: 3, [Architecture.ARM]: 3, [Architecture.MIPS]: 3 }, // Call
  1: { [Architecture.X86]: 4, [Architecture.X64]: 4, [Architecture.ARM]: 4, [Architecture.MIPS]: 4 }, // Internal Parse
  2: { [Architecture.X86]: 4, [Architecture.X64]: 4, [Architecture.ARM]: 4, [Architecture.MIPS]: 4 }, // Internal Read
  3: { [Architecture.X86]: 4, [Architecture.X64]: 4, [Architecture.ARM]: 4, [Architecture.MIPS]: 4 }, // Internal Read
};

const INT_STEP_MAPPING = {
    0: { [Architecture.X86]: 3, [Architecture.X64]: 3, [Architecture.ARM]: 3, [Architecture.MIPS]: 3 }, // Math
    1: { [Architecture.X86]: 3, [Architecture.X64]: 3, [Architecture.ARM]: 3, [Architecture.MIPS]: 3 }, // Math Wrap
    2: { [Architecture.X86]: 5, [Architecture.X64]: 5, [Architecture.ARM]: 5, [Architecture.MIPS]: 5 }, // Malloc
    3: { [Architecture.X86]: 7, [Architecture.X64]: 7, [Architecture.ARM]: 7, [Architecture.MIPS]: 7 }, // Memcpy
};

const DOUBLE_FREE_STEP_MAPPING = {
    0: { [Architecture.X86]: 3, [Architecture.X64]: 3, [Architecture.ARM]: 3, [Architecture.MIPS]: 3 }, // Malloc
    1: { [Architecture.X86]: 5, [Architecture.X64]: 5, [Architecture.ARM]: 5, [Architecture.MIPS]: 5 }, // Free 1
    2: { [Architecture.X86]: 7, [Architecture.X64]: 7, [Architecture.ARM]: 7, [Architecture.MIPS]: 7 }, // Free 2
    3: { [Architecture.X86]: 9, [Architecture.X64]: 9, [Architecture.ARM]: 9, [Architecture.MIPS]: 9 }, // Malloc 1
    4: { [Architecture.X86]: 11, [Architecture.X64]: 11, [Architecture.ARM]: 11, [Architecture.MIPS]: 11 }, // Malloc 2
};

const ROP_STEP_MAPPING = {
    0: { [Architecture.X86]: 7, [Architecture.X64]: 6, [Architecture.ARM]: 6, [Architecture.MIPS]: 6 }, // Overflow
    1: { [Architecture.X86]: 10, [Architecture.X64]: 9, [Architecture.ARM]: 9, [Architecture.MIPS]: 9 }, // Ret
    2: { [Architecture.X86]: 2, [Architecture.X64]: 2, [Architecture.ARM]: 2, [Architecture.MIPS]: 2 }, // Gadget 1
    3: { [Architecture.X86]: 15, [Architecture.X64]: 14, [Architecture.ARM]: 14, [Architecture.MIPS]: 14 }, // System
};

const HG_STEP_MAPPING = {
    0: { [Architecture.X86]: 2, [Architecture.X64]: 2, [Architecture.ARM]: 2, [Architecture.MIPS]: 2 }, // Init
    1: { [Architecture.X86]: 3, [Architecture.X64]: 3, [Architecture.ARM]: 3, [Architecture.MIPS]: 3 }, // Push 0x33
    2: { [Architecture.X86]: 6, [Architecture.X64]: 6, [Architecture.ARM]: 6, [Architecture.MIPS]: 6 }, // retf
    3: { [Architecture.X86]: 10, [Architecture.X64]: 10, [Architecture.ARM]: 10, [Architecture.MIPS]: 10 }, // 64-bit exec
    4: { [Architecture.X86]: 11, [Architecture.X64]: 11, [Architecture.ARM]: 11, [Architecture.MIPS]: 11 }, // syscall
};

const RDLL_STEP_MAPPING = {
    0: { [Architecture.X86]: 2, [Architecture.X64]: 2, [Architecture.ARM]: 2, [Architecture.MIPS]: 2 }, // ReadFile
    1: { [Architecture.X86]: 5, [Architecture.X64]: 5, [Architecture.ARM]: 5, [Architecture.MIPS]: 5 }, // VirtualAllocEx
    2: { [Architecture.X86]: 8, [Architecture.X64]: 8, [Architecture.ARM]: 8, [Architecture.MIPS]: 8 }, // WriteProcessMemory
    3: { [Architecture.X86]: 11, [Architecture.X64]: 11, [Architecture.ARM]: 11, [Architecture.MIPS]: 11 }, // GetReflectiveLoaderOffset
    4: { [Architecture.X86]: 14, [Architecture.X64]: 14, [Architecture.ARM]: 14, [Architecture.MIPS]: 14 }, // CreateRemoteThread
    5: { [Architecture.X86]: 20, [Architecture.X64]: 20, [Architecture.ARM]: 20, [Architecture.MIPS]: 20 }, // ReflectiveLoader (Target)
};

const PH_STEP_MAPPING = {
    0: { [Architecture.X86]: 6, [Architecture.X64]: 6, [Architecture.ARM]: 6, [Architecture.MIPS]: 6 }, // CreateProcess
    1: { [Architecture.X86]: 9, [Architecture.X64]: 9, [Architecture.ARM]: 9, [Architecture.MIPS]: 9 }, // NtUnmapViewOfSection
    2: { [Architecture.X86]: 12, [Architecture.X64]: 12, [Architecture.ARM]: 12, [Architecture.MIPS]: 12 }, // VirtualAllocEx
    3: { [Architecture.X86]: 15, [Architecture.X64]: 15, [Architecture.ARM]: 15, [Architecture.MIPS]: 15 }, // WriteProcessMemory
    4: { [Architecture.X86]: 19, [Architecture.X64]: 19, [Architecture.ARM]: 19, [Architecture.MIPS]: 19 }, // SetThreadContext
    5: { [Architecture.X86]: 22, [Architecture.X64]: 22, [Architecture.ARM]: 22, [Architecture.MIPS]: 22 }, // ResumeThread
};

const TH_STEP_MAPPING = {
    0: { [Architecture.X86]: 6, [Architecture.X64]: 6, [Architecture.ARM]: 6, [Architecture.MIPS]: 6 }, // OpenThread
    1: { [Architecture.X86]: 9, [Architecture.X64]: 9, [Architecture.ARM]: 9, [Architecture.MIPS]: 9 }, // SuspendThread
    2: { [Architecture.X86]: 14, [Architecture.X64]: 14, [Architecture.ARM]: 14, [Architecture.MIPS]: 14 }, // GetThreadContext
    3: { [Architecture.X86]: 18, [Architecture.X64]: 18, [Architecture.ARM]: 18, [Architecture.MIPS]: 18 }, // WriteProcessMemory
    4: { [Architecture.X86]: 22, [Architecture.X64]: 22, [Architecture.ARM]: 22, [Architecture.MIPS]: 22 }, // SetThreadContext
    5: { [Architecture.X86]: 25, [Architecture.X64]: 25, [Architecture.ARM]: 25, [Architecture.MIPS]: 25 }, // ResumeThread
};

const AES_STEP_MAPPING = {
    0: { [Architecture.X86]: 3, [Architecture.X64]: 3, [Architecture.ARM]: 3, [Architecture.MIPS]: 3 }, // AddRoundKey (Init)
    1: { [Architecture.X86]: 8, [Architecture.X64]: 8, [Architecture.ARM]: 8, [Architecture.MIPS]: 8 }, // SubBytes
    2: { [Architecture.X86]: 9, [Architecture.X64]: 9, [Architecture.ARM]: 9, [Architecture.MIPS]: 9 }, // ShiftRows
    3: { [Architecture.X86]: 10, [Architecture.X64]: 10, [Architecture.ARM]: 10, [Architecture.MIPS]: 10 }, // MixColumns
    4: { [Architecture.X86]: 11, [Architecture.X64]: 11, [Architecture.ARM]: 11, [Architecture.MIPS]: 11 }, // AddRoundKey
};

const CODES = {
  [ExploitType.STACK]: {
    [Architecture.X86]: `push   ebp
mov    ebp, esp
sub    esp, 0x10
lea    eax, [ebp-0x8]
push   DWORD PTR [ebp+0x8]
push   eax
call   strcpy           ; <--- VULN
leave
ret`,
    [Architecture.X64]: `push   rbp
mov    rbp, rsp
sub    rsp, 0x10
lea    rax, [rbp-0x8]
mov    rsi, rdx
mov    rdi, rax
call   strcpy           ; <--- VULN
leave
ret`,
    [Architecture.ARM]: `push   {fp, lr}
add    fp, sp, #4
sub    sp, sp, #16
mov    r0, sp
bl     strcpy           ; <--- VULN
sub    sp, fp, #4
pop    {fp, pc}`,
    [Architecture.MIPS]: `addiu  sp, sp, -32
sw     ra, 28(sp)
sw     fp, 24(sp)
move   fp, sp
jal    strcpy           ; <--- VULN
move   sp, fp
lw     fp, 24(sp)
lw     ra, 28(sp)
addiu  sp, sp, 32
jr     ra`,
  },
  [ExploitType.HEAP]: {
    [Architecture.X86]: `push   0x10
call   malloc           ; chunk1
mov    [ebp-4], eax
push   0x10
call   malloc           ; chunk2
mov    [ebp-8], eax
push   [ebp+8]
push   [ebp-4]
call   strcpy           ; <--- OVERFLOW
push   [ebp-8]
call   free             ; <--- CRASH`,
    [Architecture.X64]: `mov    edi, 0x10
call   malloc           ; chunk1
mov    [rbp-8], rax
mov    edi, 0x10
call   malloc           ; chunk2
mov    [rbp-16], rax
mov    rsi, [rbp+16]
mov    rdi, [rbp-8]
call   strcpy           ; <--- OVERFLOW
mov    rdi, [rbp-16]
call   free             ; <--- CRASH`,
    [Architecture.ARM]: `mov    r0, #16
bl     malloc           ; chunk1
str    r0, [fp, #-8]
mov    r0, #16
bl     malloc           ; chunk2
str    r0, [fp, #-12]
ldr    r1, [fp, #4]
ldr    r0, [fp, #-8]
bl     strcpy           ; <--- OVERFLOW
ldr    r0, [fp, #-12]
bl     free             ; <--- CRASH`,
    [Architecture.MIPS]: `li     a0, 16
jal    malloc           ; chunk1
sw     v0, 24(fp)
li     a0, 16
jal    malloc           ; chunk2
sw     v0, 28(fp)
lw     a1, 40(fp)
lw     a0, 24(fp)
jal    strcpy           ; <--- OVERFLOW
lw     a0, 28(fp)
jal    free             ; <--- CRASH`,
  },
  [ExploitType.UAF]: {
    [Architecture.X86]: `push   0x10
call   malloc           ; Alloc A
mov    [ebp-4], eax     ; ptr1 = A
push   [ebp-4]
call   free             ; Free(ptr1)
; ptr1 NOT CLEARED
push   0x10
call   malloc           ; Alloc B (Reuses A)
mov    [ebp-8], eax     ; ptr2 = B
mov    eax, [ebp-4]     ; Load ptr1 (Dangling)
push   eax
call   printf           ; Use ptr1 -> ACCESS B`,
    [Architecture.X64]: `mov    edi, 0x10
call   malloc           ; Alloc A
mov    [rbp-8], rax     ; ptr1
mov    rdi, [rbp-8]
call   free             ; Free ptr1
mov    edi, 0x10
call   malloc           ; Alloc B
mov    [rbp-16], rax    ; ptr2
mov    rsi, [rbp-8]     ; Load ptr1
mov    rdi, fmt
call   printf           ; Use ptr1`,
    [Architecture.ARM]: `mov    r0, #16
bl     malloc           ; Alloc A
str    r0, [fp, #-8]
ldr    r0, [fp, #-8]
bl     free             ; Free A
mov    r0, #16
bl     malloc           ; Alloc B
str    r0, [fp, #-12]
ldr    r1, [fp, #-8]    ; Load ptr1
ldr    r0, =fmt
bl     printf           ; Use ptr1`,
    [Architecture.MIPS]: `li     a0, 16
jal    malloc
sw     v0, 24(fp)       ; ptr1
lw     a0, 24(fp)
jal    free
li     a0, 16
jal    malloc           ; ptr2
sw     v0, 28(fp)
lw     a1, 24(fp)       ; ptr1
la     a0, fmt
jal    printf`,
  },
  [ExploitType.FORMAT_STRING]: {
    [Architecture.X86]: `lea    eax, [ebp-0x40]  ; buf
push   eax
call   printf           ; printf(buf) - NO FMT
add    esp, 4
; Internal printf loops stack...`,
    [Architecture.X64]: `lea    rax, [rbp-0x40]
mov    rdi, rax         ; arg1 = buf
mov    eax, 0
call   printf           ; printf(buf)
; Internal printf loops stack...`,
    [Architecture.ARM]: `sub    r3, fp, #64
mov    r0, r3           ; r0 = buf
bl     printf           ; printf(buf)
; Internal printf loops stack...`,
    [Architecture.MIPS]: `addiu  a0, fp, -64      ; a0 = buf
jal    printf
; Internal printf loops stack...`,
  },
  [ExploitType.INTEGER_OVERFLOW]: {
    [Architecture.X86]: `mov    al, [ebp+8]    ; Load len (u8)
add    al, 20         ; Add 20 -> WRAP!
movzx  eax, al        ; Zero extend (result: 4)
push   eax
call   malloc         ; malloc(4)
push   [ebp+8]        ; Push len (240)
push   [ebp-4]        ; Push data
push   eax            ; Push buf
call   memcpy         ; memcpy(buf, data, 240)`,
    [Architecture.X64]: `movzx  eax, BYTE PTR [rbp-8]
add    al, 20         ; Wraparound!
movzx  edi, al
call   malloc         ; malloc(4)
mov    rdi, rax
mov    rsi, [rbp-16]
movzx  rdx, BYTE PTR [rbp-8]
call   memcpy         ; memcpy(..., 240)`,
    [Architecture.ARM]: `ldrb   r0, [fp, #-8]  ; Load len
add    r0, r0, #20    ; Add 20
and    r0, r0, #0xFF  ; Simulating u8 cast
bl     malloc         ; malloc(wrapped)
ldrb   r2, [fp, #-8]  ; Load original len
bl     memcpy         ; memcpy overflow`,
    [Architecture.MIPS]: `lbu    t0, 0(a0)      ; Load len
addiu  t1, t0, 20     ; Add 20
andi   a0, t1, 0xFF   ; Wrap to 8-bit
jal    malloc
move   a0, v0
move   a2, t0         ; Original len
jal    memcpy`,
  },
  [ExploitType.DOUBLE_FREE]: {
    [Architecture.X86]: `push   0x10
call   malloc           ; Alloc ptr
mov    [ebp-4], eax
push   [ebp-4]
call   free             ; Free(ptr)
push   [ebp-4]
call   free             ; Free(ptr) again!
push   0x10
call   malloc           ; Alloc p1
mov    [ebp-8], eax
push   0x10
call   malloc           ; Alloc p2 (Same Addr!)
mov    [ebp-12], eax`,
    [Architecture.X64]: `mov    edi, 0x10
call   malloc           ; Alloc ptr
mov    [rbp-8], rax
mov    rdi, [rbp-8]
call   free             ; Free(ptr)
mov    rdi, [rbp-8]
call   free             ; Free(ptr) again!
mov    edi, 0x10
call   malloc           ; Alloc p1
mov    [rbp-16], rax
mov    edi, 0x10
call   malloc           ; Alloc p2 (Same Addr!)
mov    [rbp-24], rax`,
    [Architecture.ARM]: `mov    r0, #16
bl     malloc           ; Alloc ptr
str    r0, [fp, #-8]
ldr    r0, [fp, #-8]
bl     free             ; Free(ptr)
ldr    r0, [fp, #-8]
bl     free             ; Free(ptr) again!
mov    r0, #16
bl     malloc           ; Alloc p1
str    r0, [fp, #-12]
mov    r0, #16
bl     malloc           ; Alloc p2
str    r0, [fp, #-16]`,
    [Architecture.MIPS]: `li     a0, 16
jal    malloc           ; Alloc ptr
sw     v0, 24(fp)
lw     a0, 24(fp)
jal    free             ; Free(ptr)
lw     a0, 24(fp)
jal    free             ; Free(ptr) again!
li     a0, 16
jal    malloc           ; Alloc p1
sw     v0, 28(fp)
li     a0, 16
jal    malloc           ; Alloc p2
sw     v0, 32(fp)`,
  },
  [ExploitType.ROP]: {
      [Architecture.X86]: `; GADGETS IN TEXT SEGMENT
0x401105: pop edi; ret
0x401040: <system function>

; VULNERABLE FUNCTION
call gets       ; Stack Overflow
leave
ret             ; Pops 0x401105`,
      [Architecture.X64]: `; GADGETS IN TEXT SEGMENT
0x401105: pop rdi; ret
0x401040: <system function>

; VULNERABLE FUNCTION
call gets       ; Stack Overflow
leave
ret             ; Pops 0x401105`,
      [Architecture.ARM]: `; GADGETS
0x401105: pop {r0, pc}
0x401040: <system function>

; VULN
bl gets
pop {fp, pc}    ; Pops 0x401105`,
      [Architecture.MIPS]: `; GADGETS
0x401105: lw a0, 0(sp); jr ra
0x401040: <system function>

; VULN
jal gets
lw ra, 28(sp)
jr ra           ; Jumps to 0x401105`,
  },
  [ExploitType.HEAVENS_GATE]: {
      [Architecture.X86]: `; Mode: 32-bit (WoW64)
push 0x33          ; Push 64-bit CS Selector
call next          ; Push EIP
next:
add dword [esp], 5 ; Adjust Ret Addr
retf               ; Far Return -> ENTER GATE

; Mode: 64-bit (Native)
mov rax, 0x123456789ABC
syscall            ; Direct Syscall
retf               ; Return to 32-bit`,
      [Architecture.X64]: `; Already in 64-bit mode. 
; Heaven's Gate is a technique for 32-bit (WoW64) 
; processes to execute 64-bit instructions.`,
      [Architecture.ARM]: `; Not applicable.`,
      [Architecture.MIPS]: `; Not applicable.`,
  },
  [ExploitType.REFLECTIVE_DLL]: {
      [Architecture.X86]: `call ReadFile           ; Read DLL
push PAGE_EXECUTE_READWRITE
call VirtualAllocEx     ; Alloc Remote Memory
call WriteProcessMemory ; Inject DLL Headers+Sections
call GetReflectiveLoaderOffset
call CreateRemoteThread ; Start Loader

; --- IN TARGET ---
ReflectiveLoader:
  call GetPEB
  call LoadLibrary
  call ProcessRelocations
  call DllMain`,
      [Architecture.X64]: `call ReadFile
mov  rdx, PAGE_EXECUTE_READWRITE
call VirtualAllocEx
call WriteProcessMemory
call GetReflectiveLoaderOffset
call CreateRemoteThread

; --- IN TARGET ---
ReflectiveLoader:
  call GetPEB
  call LoadLibrary
  call ProcessRelocations
  call DllMain`,
      [Architecture.ARM]: `bl ReadFile
mov r1, #PAGE_EXEC_RW
bl VirtualAllocEx
bl WriteProcessMemory
bl GetReflectiveLoaderOffset
bl CreateRemoteThread

; --- IN TARGET ---
ReflectiveLoader:
  bl GetPEB
  bl ProcessRelocations`,
      [Architecture.MIPS]: `jal ReadFile
li  a1, PAGE_EXEC_RW
jal VirtualAllocEx
jal WriteProcessMemory
jal CreateRemoteThread`,
  },
  [ExploitType.PROCESS_HOLLOWING]: {
      [Architecture.X86]: `push CREATE_SUSPENDED
call CreateProcess      ; Start Zombie Process
call NtUnmapViewOfSection ; Hollow it
call VirtualAllocEx     ; Alloc Payload Mem
call WriteProcessMemory ; Inject Payload
call GetThreadContext   ; Get CPU State
call SetThreadContext   ; Set EIP to Payload
call ResumeThread       ; Run!`,
      [Architecture.X64]: `mov  rdx, CREATE_SUSPENDED
call CreateProcess
call NtUnmapViewOfSection
call VirtualAllocEx
call WriteProcessMemory
call GetThreadContext
call SetThreadContext
call ResumeThread`,
      [Architecture.ARM]: `bl CreateProcess
bl NtUnmapViewOfSection
bl VirtualAllocEx
bl WriteProcessMemory
bl GetThreadContext
bl SetThreadContext
bl ResumeThread`,
      [Architecture.MIPS]: `jal CreateProcess
jal NtUnmapViewOfSection
jal VirtualAllocEx
jal WriteProcessMemory
jal GetThreadContext
jal SetThreadContext
jal ResumeThread`,
  },
  [ExploitType.THREAD_HIJACKING]: {
      [Architecture.X86]: `call OpenThread         ; Access Target
call SuspendThread      ; Freeze it
call GetThreadContext   ; Get EIP
call VirtualAllocEx     ; Alloc Shellcode
call WriteProcessMemory ; Inject Shellcode
mov  [ctx.Eip], eax     ; Update EIP in struct
call SetThreadContext   ; Apply changes
call ResumeThread       ; Exec Shellcode`,
      [Architecture.X64]: `call OpenThread
call SuspendThread
call GetThreadContext
call VirtualAllocEx
call WriteProcessMemory
mov  [ctx.Rip], rax
call SetThreadContext
call ResumeThread`,
      [Architecture.ARM]: `bl OpenThread
bl SuspendThread
bl GetThreadContext
bl VirtualAllocEx
bl WriteProcessMemory
bl SetThreadContext
bl ResumeThread`,
      [Architecture.MIPS]: `jal OpenThread
jal SuspendThread
jal GetThreadContext
jal VirtualAllocEx
jal WriteProcessMemory
jal SetThreadContext
jal ResumeThread`,
  },
  [ExploitType.SQLI]: {
      [Architecture.X86]: "; PHP Logic - No Assembly",
      [Architecture.X64]: "; PHP Logic - No Assembly",
      [Architecture.ARM]: "; PHP Logic - No Assembly",
      [Architecture.MIPS]: "; PHP Logic - No Assembly",
  },
  [ExploitType.SSRF]: {
      [Architecture.X86]: "; PHP Logic - No Assembly",
      [Architecture.X64]: "; PHP Logic - No Assembly",
      [Architecture.ARM]: "; PHP Logic - No Assembly",
      [Architecture.MIPS]: "; PHP Logic - No Assembly",
  },
  [ExploitType.CSRF]: {
      [Architecture.X86]: "; PHP Logic - No Assembly",
      [Architecture.X64]: "; PHP Logic - No Assembly",
      [Architecture.ARM]: "; PHP Logic - No Assembly",
      [Architecture.MIPS]: "; PHP Logic - No Assembly",
  },
  [ExploitType.LOG4SHELL]: {
      [Architecture.X86]: "; Java Logic - No Assembly",
      [Architecture.X64]: "; Java Logic - No Assembly",
      [Architecture.ARM]: "; Java Logic - No Assembly",
      [Architecture.MIPS]: "; Java Logic - No Assembly",
  },
  [ExploitType.NEXTJS_RCE]: {
      [Architecture.X86]: "; JavaScript/Node.js Logic - No Assembly",
      [Architecture.X64]: "; JavaScript/Node.js Logic - No Assembly",
      [Architecture.ARM]: "; JavaScript/Node.js Logic - No Assembly",
      [Architecture.MIPS]: "; JavaScript/Node.js Logic - No Assembly",
  },
  [ExploitType.XXE]: {
      [Architecture.X86]: "; XML Parser Logic - No Assembly",
      [Architecture.X64]: "; XML Parser Logic - No Assembly",
      [Architecture.ARM]: "; XML Parser Logic - No Assembly",
      [Architecture.MIPS]: "; XML Parser Logic - No Assembly",
  },
  [ExploitType.XSS]: {
      [Architecture.X86]: "; Browser/JS Logic - No Assembly",
      [Architecture.X64]: "; Browser/JS Logic - No Assembly",
      [Architecture.ARM]: "; Browser/JS Logic - No Assembly",
      [Architecture.MIPS]: "; Browser/JS Logic - No Assembly",
  },
  [ExploitType.DESERIALIZATION]: {
      [Architecture.X86]: "; PHP/Object Logic - No Assembly",
      [Architecture.X64]: "; PHP/Object Logic - No Assembly",
      [Architecture.ARM]: "; PHP/Object Logic - No Assembly",
      [Architecture.MIPS]: "; PHP/Object Logic - No Assembly",
  },
  [ExploitType.AES]: {
      [Architecture.X86]: `AES_Encrypt:
  movdqu  xmm0, [rcx]      ; Load State
  pxor    xmm0, [rdx]      ; AddRoundKey (Init)
  ...
  aesenc  xmm0, [rdx+16]   ; Round 1 (Hardware AES)
  aesenc  xmm0, [rdx+32]   ; Round 2
  ...
  aesenclast xmm0, [rdx+...] ; Final Round`,
      [Architecture.X64]: `AES_Encrypt:
  movdqu  xmm0, [rcx]      ; Load State
  pxor    xmm0, [rdx]      ; AddRoundKey (Init)
  ...
  aesenc  xmm0, [rdx+16]   ; Round 1
  aesenc  xmm0, [rdx+32]   ; Round 2
  ...
  aesenclast xmm0, [rdx+...] ; Final Round`,
      [Architecture.ARM]: `vld1.8  {q0}, [r0]       ; Load State
veor    q0, q0, q1       ; AddRoundKey
aese.8  q0, q2           ; AES Encrypt (Sub+Shift+Mix)
aesmc.8 q0, q0           ; Mix Columns
...`,
      [Architecture.MIPS]: `; MIPS usually doesn't have AES NI
; It uses lookup tables (T-Tables)
lw      t0, 0(a0)        ; Load state byte
la      t1, Te0          ; Load address of T-Table (Look for this!)
addu    t2, t1, t0       ; Index into table
lw      t3, 0(t2)        ; SubBytes+Shift+Mix lookup
...`,
  }
};

export const AssemblyViewer: React.FC<AssemblyViewerProps> = ({ type, arch, stepId }) => {
  const code = CODES[type][arch] || "No code available";
  
  let highlightLine = -1;
  if (type === ExploitType.STACK) {
      // @ts-ignore
      highlightLine = STACK_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.HEAP) {
      // @ts-ignore
      highlightLine = HEAP_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.UAF) {
      // @ts-ignore
      highlightLine = UAF_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.FORMAT_STRING) {
      // @ts-ignore
      highlightLine = FMT_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.INTEGER_OVERFLOW) {
      // @ts-ignore
      highlightLine = INT_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.DOUBLE_FREE) {
      // @ts-ignore
      highlightLine = DOUBLE_FREE_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.ROP) {
      // @ts-ignore
      highlightLine = ROP_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.HEAVENS_GATE) {
      // @ts-ignore
      highlightLine = HG_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.REFLECTIVE_DLL) {
      // @ts-ignore
      highlightLine = RDLL_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.PROCESS_HOLLOWING) {
      // @ts-ignore
      highlightLine = PH_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.THREAD_HIJACKING) {
      // @ts-ignore
      highlightLine = TH_STEP_MAPPING[stepId]?.[arch] || -1;
  } else if (type === ExploitType.AES) {
      // @ts-ignore
      highlightLine = AES_STEP_MAPPING[stepId]?.[arch] || -1;
  }

  return (
    <div className="w-full max-w-2xl mx-auto mt-4">
      <div className="bg-[#1e1e1e] border border-gray-600 rounded-sm shadow-xl overflow-hidden">
        {/* Header */}
        <div className="bg-[#2d2d2d] px-3 py-2 border-b border-gray-600 flex justify-between items-center">
            <div className="flex items-center gap-2 text-gray-300 text-xs font-bold uppercase tracking-wider">
                <Cpu size={14} className="text-purple-400" />
                Disassembly ({arch})
            </div>
            <div className="text-[10px] text-gray-500 font-mono">.text section</div>
        </div>

        {/* Code Body */}
        <div className="p-4 font-mono text-xs overflow-x-auto">
            <table className="w-full text-left border-collapse">
                <tbody>
                    {code.split('\n').map((line, idx) => {
                        const lineNum = idx + 1;
                        const isHighlighted = lineNum === highlightLine;
                        return (
                            <tr key={idx} className={`${isHighlighted ? 'bg-[#37373d]' : ''} transition-colors duration-200`}>
                                <td className="w-8 text-gray-600 text-right pr-4 select-none">{lineNum}</td>
                                <td className={`${isHighlighted ? 'text-blue-300 font-bold' : 'text-gray-400'} whitespace-pre`}>
                                    {line}
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
        
        {/* Status Bar */}
        <div className="bg-[#007acc] px-2 py-1 text-[10px] text-white flex justify-end">
            <span>{highlightLine !== -1 ? 'INSTRUCTION POINTER ACTIVE' : 'WAITING'}</span>
        </div>
      </div>
    </div>
  );
};
