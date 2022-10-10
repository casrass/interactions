# Interactions in malware

## Outline
- Explain the concept of interacting with pointers and how this applies to memory hacking
- Introduce different ways of interacting with memory with the Windows WinAPI
- Discuss different anti-tamper measures commonly used in malicious software and cover some ways that you can counter them
- Apply this knowledge to a red-blue team scenario

## Key terms

### Pointers
- Named because they “point” to specific objects in memory
- Can be displayed as unsigned integers, and can have the same mathematical operations applied as normal values
- Are 8 bytes long on 64-bit programs, and 4 bytes on 32-bit (64 bits = 8 bytes, etc.)

### Assembly code
- As close-to-hardware as possible, without directly modifying the chip
- Contains a variety of different operations for stack management, heap access and mathematical calculations
- Syntax is different across different architectures

### Machine code
- Machine code is assembly code that has been “assembled”
- Resembles a string of bytes that gets sequentially executed by the processor
- Arbitrarily injected machine code from an external process can be known as “shellcode”

### Stack vs Heap

#### Stack
- Contains code used specifically for that thread of execution
- Is executed sequentially, one after the other, like a stack of paper

#### Heap
- Dynamically allocated during runtime, and there is no set structure
- A load of data, a “heap” if u may

## Debug Prevention

### Analysis
- Check IsBeingDebugged flag locally
- Check IsDebuggerPresent flag in system processes
- Check if NtQuerySystemInformation has been hooked

### Prevention
- Patch DbgBreakPoint
- Patch DbgUiRemoteBreakin
