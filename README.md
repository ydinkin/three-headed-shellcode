# Three Headed Shellcode
## Challenge
Create a single shellcode that supports x86, arm & mipsl.
This multi-architecture shellcode will receive 2 integers via registers:
- x86: EAX, EBX
- ARM: R0, R1
- MIPS: A0, A1

It must return the sum of said integers via the first register, and their product via the second.

## Execution
The shellcode's execution will be emulated by [Unicorn](https://github.com/ekse/unicorn-rs) via the provided test utility.

The code will be loaded into address 0x00000000. The address space is limited to the shellcode's size (aligned to 4KB).

All state (other then the registers mentioned above) will be initialized to Unicorn's default - mostly zeroes.

Exceptions, interrupts and other unhandled behaviours wil cause the emulation to stop & the current state to be considered as the shellcode's result.

In order to avoid infinite loops, emulation time is limited to 1 second.

100 rounds will be emulated for each architecture with random integers, and each successful run will award 1 point.

In case of a tie, the smallest shellcode shall win.

## Examples
Shellcodes with a naive implementation for each architecture are provided [here](examples). 

Said examples award 100 points each (since they only work on a single architecture).

## Known Issues

- Building the unicorn-rs crate may require MSVC build tools (v110_xp).

