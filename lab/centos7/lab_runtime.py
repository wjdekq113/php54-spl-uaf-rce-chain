#!/usr/bin/env python3
"""Shared host-side helpers for the isolated CentOS 7 reproduction lab."""
from __future__ import annotations

import os
import re
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

MAP_LINE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$"
)


@dataclass(frozen=True)
class ContainerProcess:
    host_pid: int
    container_pid: int
    args: str


def run(argv: Sequence[str], *, check: bool = True, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        check=check,
        timeout=timeout,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def podman_exec(container: str, argv: Sequence[str], *, check: bool = True, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    return run(["podman", "exec", container, *argv], check=check, timeout=timeout)


def top_processes(container: str) -> list[ContainerProcess]:
    result = run(["podman", "top", container, "hpid,pid,args"])
    processes: list[ContainerProcess] = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.strip().split(None, 2)
        if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        processes.append(ContainerProcess(int(fields[0]), int(fields[1]), fields[2]))
    return processes


def wait_for_process(
    container: str,
    predicate: Callable[[ContainerProcess], bool],
    *,
    exclude_host_pids: set[int] | None = None,
    timeout: float = 10.0,
) -> ContainerProcess:
    excluded = exclude_host_pids or set()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for process in top_processes(container):
            if process.host_pid not in excluded and predicate(process):
                return process
        time.sleep(0.1)
    raise RuntimeError("timed out waiting for the container process")


def mapping_bases(pid: int) -> dict[str, tuple[int, str]]:
    bases: dict[str, tuple[int, str]] = {}
    with open(f"/proc/{pid}/maps", encoding="ascii") as handle:
        for line in handle:
            match = MAP_LINE.match(line.rstrip("\n"))
            if not match:
                continue
            path = match.group(5).strip()
            if not path.startswith("/"):
                continue
            start = int(match.group(1), 16)
            offset = int(match.group(4), 16)
            base = start - offset
            name = os.path.basename(path)
            current = bases.get(name)
            if current is None or base < current[0]:
                bases[name] = (base, path)
    return bases


def select_mapping(bases: dict[str, tuple[int, str]], prefixes: tuple[str, ...]) -> tuple[int, str]:
    for name, value in bases.items():
        if name.startswith(prefixes):
            return value
    raise RuntimeError(f"mapping not found for prefixes: {', '.join(prefixes)}")


def read_qword(pid: int, address: int) -> int:
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as handle:
        handle.seek(address)
        data = handle.read(8)
    if len(data) != 8:
        raise RuntimeError(f"short /proc/{pid}/mem read at {address:#x}")
    return struct.unpack("<Q", data)[0]


def relocation_offset(container: str, path: str, symbol: str) -> int:
    result = podman_exec(container, ["readelf", "-rW", path])
    for line in result.stdout.splitlines():
        if "JUMP_SLOT" in line and symbol in line:
            return int(line.split()[0], 16)
    raise RuntimeError(f"no JUMP_SLOT relocation for {symbol} in {path}")


def dynamic_symbol_offset(container: str, path: str, symbol: str) -> int:
    result = podman_exec(container, ["nm", "-D", "--defined-only", path])
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2].split("@", 1)[0] == symbol:
            return int(fields[0], 16)
    raise RuntimeError(f"dynamic symbol {symbol} not found in {path}")


def build_id(container: str, path: str) -> str:
    result = podman_exec(container, ["readelf", "-n", path])
    for line in result.stdout.splitlines():
        if "Build ID:" in line:
            return line.split("Build ID:", 1)[1].strip()
    raise RuntimeError(f"Build ID not found in {path}")


def sha256_in_container(container: str, path: str) -> str:
    result = podman_exec(container, ["sha256sum", path])
    return result.stdout.split()[0]


def package_nevra(container: str, packages: Sequence[str]) -> list[str]:
    query = r"%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"
    result = podman_exec(container, ["rpm", "-q", "--qf", query, *packages])
    return [line for line in result.stdout.splitlines() if line]


def marker_stat(path: Path) -> dict[str, int | str]:
    stat = path.stat()
    return {
        "path": path.name,
        "size": stat.st_size,
        "inode": stat.st_ino,
        "mtime_ns": stat.st_mtime_ns,
    }
