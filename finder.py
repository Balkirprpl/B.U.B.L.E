import angr, claripy
import os, subprocess
import logging
import argparse
import ropgadget
from pwn import *
import sys

def is_win(e):
    try:
        win = e.sym['win']
        return True
    except:
        return False

def is_system(e):
    if "system" in e.sym.keys():
        return True
    else:
        return False

def is_execv(e):
    if "execve" in e.sym.keys():
        return True
    else:
        return False

def is_syscall(e):
    if "syscall" in e.sym.keys():
        return True
    else:
        return False

def is_puts(e):
    if "puts" in e.sym.keys():
        return True
    else:
        return False

def is_printf(e):
    if "printf" in e.sym.keys():
        return True
    else:
        return False

def solve_ret2win(e):
    win = e.symbols['win']
    #win = hex(win)
    project = angr.Project(binary)

    simulation = project.factory.simgr()
    simulation.explore(find=win)

    if simulation.found:
        ans = simulation.found[0]
        print(ans)


# run: python3 finder.py <binary-name>
if __name__ == "__main__":
    binary = "./test-binaries/" + sys.argv[1]
    e = ELF(binary)
    #print(e.sym.keys())

    # Checks the symbol map
    # looking for the type of exploit
    # missing:
    #   -- write-gadgets
    #   -- rop-parameters
    #   -- ret2one
    #   -- got-overwrite
    if is_win(e):
        print("ret2win")
        solve_ret2win(e)
    elif is_system(e):
        print("ret2sys")
    elif is_execv(e):
        print("execv")
    elif is_syscall(e):
        print("syscall")
    elif is_puts(e):
        print("puts")
    elif is_printf(e):
        print("printf")
