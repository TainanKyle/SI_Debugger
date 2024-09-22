# Simple Instruction Level Debugger

### Introduction
Implement a simple instruction-level debugger that allows a user to debug a program interactively at the assembly instruction level.
The debugger is implemented by using the ptrace interface.

### Available Commands
- Load Program
- Step Instruction
- Continue
- Info Registers
- Set Breakpoints
- Delete Breakpoints
- Info Breakpoints
- Patch Memory
- System Call

### Demo
#### Demo 1
Command: `./sdb ./hello`

Input:
```
break 0x401005
break 40102b
info break
si
si
cont
info reg
cont
```

Output:
```
** program './hello' loaded. entry point 0x401000.
      401000: f3 0f 1e fa                     	endbr64   
      401004: 55                              	push      rbp
      401005: 48 89 e5                        	mov       rbp, rsp
      401008: ba 0e 00 00 00                  	mov       edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00            	lea       rax, [rip + 0xfec]
(sdb) break 0x401005
** set a breakpoint at 0x401005.
(sdb) break 40102b
** set a breakpoint at 0x40102b.
(sdb) info break
Num	Address		
0	0x401005
1	0x40102b
(sdb) si
      401004: 55                              	push      rbp
      401005: 48 89 e5                        	mov       rbp, rsp
      401008: ba 0e 00 00 00                  	mov       edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00            	lea       rax, [rip + 0xfec]
      401014: 48 89 c6                        	mov       rsi, rax
(sdb) si
** hit a breakpoint at 0x401005.
      401005: 48 89 e5                        	mov       rbp, rsp
      401008: ba 0e 00 00 00                  	mov       edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00            	lea       rax, [rip + 0xfec]
      401014: 48 89 c6                        	mov       rsi, rax
      401017: bf 01 00 00 00                  	mov       edi, 1
(sdb) cont
** hit a breakpoint at 0x40102b.
      40102b: b8 01 00 00 00                  	mov       eax, 1
      401030: 0f 05                           	syscall   
      401032: c3                              	ret       
      401033: b8 00 00 00 00                  	mov       eax, 0
      401038: 0f 05                           	syscall   
(sdb) info reg
$rax 0x0000000000402000    $rbx 0x0000000000000000    $rcx 0x0000000000000000
$rdx 0x000000000000000e    $rsi 0x0000000000402000    $rdi 0x0000000000000001
$rbp 0x00007ffe0e5cd5b8    $rsp 0x00007ffe0e5cd5b0    $r8  0x0000000000000000
$r9  0x0000000000000000    $r10 0x0000000000000000    $r11 0x0000000000000000
$r12 0x0000000000000000    $r13 0x0000000000000000    $r14 0x0000000000000000
$r15 0x0000000000000000    $rip 0x000000000040102b    $eflags 0x0000000000000202
(sdb) cont
hello world!
** the target program terminated.
```

#### Demo 2
Command: `./sdb ./guess`

Input:
```
break 0x4010de
cont
1
patch 0x4010e8 0x9090 2
si
info break
delete 0
break 0x4010ea
delete 0
info break
cont
patch 0x402015 0x4e49570a 4
cont
```

Output:
```
** program './guess' loaded. entry point 0x40108b.
      40108b: f3 0f 1e fa                       endbr64
      40108f: 55                                push      rbp
      401090: 48 89 e5                          mov       rbp, rsp
      401093: 48 83 ec 10                       sub       rsp, 0x10
      401097: ba 12 00 00 00                    mov       edx, 0x12
(sdb) break 0x4010de
** set a breakpoint at 0x4010de.
(sdb) cont
guess a number > 1
** hit a breakpoint at 0x4010de.
      4010de: 48 89 c7                          mov       rdi, rax
      4010e1: e8 1a ff ff ff                    call      0x401000
      4010e6: 85 c0                             test      eax, eax
      4010e8: 75 1b                             jne       0x401105
      4010ea: ba 06 00 00 00                    mov       edx, 6
(sdb) patch 0x4010e8 0x9090 2
** patch memory at address 0x4010e8.
(sdb) si
      4010e1: e8 1a ff ff ff                    call      0x401000
      4010e6: 85 c0                             test      eax, eax
      4010e8: 90                                nop
      4010e9: 90                                nop
      4010ea: ba 06 00 00 00                    mov       edx, 6
(sdb) info break
Num	Address		
0	0x4010de
(sdb) delete 0
** delete breakpoint 0.
(sdb) break 0x4010ea
** set a breakpoint at 0x4010ea.
(sdb) delete 0
** breakpoint 0 does not exist.
(sdb) info break
Num	Address		
1	0x4010ea
(sdb) cont
** hit a breakpoint at 0x4010ea.
      4010ea: ba 06 00 00 00                    mov       edx, 6
      4010ef: 48 8d 05 1f 0f 00 00              lea       rax, [rip + 0xf1f]
      4010f6: 48 89 c6                          mov       rsi, rax
      4010f9: bf 01 00 00 00                    mov       edi, 1
      4010fe: e8 25 00 00 00                    call      0x401128
(sdb) patch 0x402015 0x4e49570a 4
** patch memory at address 0x402015.
(sdb) cont

WIN
** the target program terminated.
```
