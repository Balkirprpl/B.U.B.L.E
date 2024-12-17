from pwn import *
import time
def find_pad(binary):
    p = process(binary)
    p.sendline(cyclic(5000, n=8))
    p.wait()
    #p.interactive()
    #time.sleep(10)
    core = p.corefile
    p.close()
    os.remove(core.file.name)
    padding = int(cyclic_find(core.read(core.rsp, 8), n=8))
    print(f"padding found: {padding}")
    print(cyclic(padding))
    if padding < 0:
        print(f"not found, checking rbp")
        padding = int(cyclic_find(core.read(core.rbp, 8), n=8))
        if padding < 0:
            print("not found")
            return False

    return int(padding)


if __name__ == "__main__":
    find_pad("test-binaries/" + sys.argv[1])
