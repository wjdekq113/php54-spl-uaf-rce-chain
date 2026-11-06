#!/usr/bin/env python3
"""Build the isolated lab, run all cases, and write reproducible evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from lab.centos7.lab_runtime import (  # noqa: E402
    build_id,
    package_nevra,
    podman_exec,
    relocation_offset,
    run,
    sha256_in_container,
)
from lab.centos7.verify_aslr_chain import run_case as run_aslr_case  # noqa: E402
from lab.centos7.verify_php_cgi import run_case as run_cgi_case  # noqa: E402
from lab.centos7.verify_php_fpm import run_case as run_fpm_case  # noqa: E402

DEFAULT_IMAGE = "php54-spl-uaf-lab:local"
PHP_SOURCE_URL = "https://museum.php.net/php5/php-5.4.44.tar.gz"
PHP_SOURCE_SHA256 = "1799998e48da3d8f34722840628e18789e26ea21741d4e498ade6749b3266602"
BASE_IMAGE_DIGEST = "sha256:dead07b4d8ed7e29e98de0f4504d87e8880d4347859d839686a31da35a3b532f"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_image(image: str) -> None:
    subprocess.run(
        [
            "podman", "build", "--arch", "amd64", "--format", "docker", "--tag", image,
            "--file", str(HERE / "Containerfile"), str(ROOT),
        ],
        check=True,
    )


def image_metadata(image: str) -> dict[str, object]:
    raw = run(["podman", "image", "inspect", image]).stdout
    data = json.loads(raw)[0]
    return {
        "id": data.get("Id"),
        "digest": data.get("Digest"),
        "repo_digests": data.get("RepoDigests", []),
        "architecture": data.get("Architecture"),
        "created": data.get("Created"),
    }


def collect_environment(container: str, image: str) -> dict[str, object]:
    binaries = [
        "/usr/bin/php-cgi",
        "/usr/sbin/php-fpm",
        "/opt/php-5.4.44/bin/php-cgi",
        "/lib64/libpthread-2.17.so",
        "/lib64/libc-2.17.so",
        "/lib64/ld-2.17.so",
    ]
    versions = {
        "vendor_php": podman_exec(container, ["/usr/bin/php-cgi", "-v"]).stdout.splitlines()[:2],
        "patched_php": podman_exec(container, ["/opt/php-5.4.44/bin/php-cgi", "-v"]).stdout.splitlines()[:2],
        "container_uname": podman_exec(container, ["uname", "-a"]).stdout.strip(),
        "podman": run(["podman", "--version"]).stdout.strip(),
        "host_python": platform.python_version(),
        "host_platform": platform.platform(),
    }
    try:
        ptrace_scope = Path("/proc/sys/kernel/yama/ptrace_scope").read_text(encoding="ascii").strip()
    except FileNotFoundError:
        ptrace_scope = "not-present"

    relocation = podman_exec(container, ["readelf", "-rW", "/lib64/libpthread-2.17.so"]).stdout
    relocation_lines = [line.strip() for line in relocation.splitlines() if "__libc_system" in line]
    verify = podman_exec(
        container,
        ["rpm", "-V", "php-cli", "php-common", "glibc"],
        check=False,
    )
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "base_image_digest": BASE_IMAGE_DIGEST,
        "lab_image": image_metadata(image),
        "php_5_4_44_source": {"url": PHP_SOURCE_URL, "sha256": PHP_SOURCE_SHA256},
        "containerfile_sha256": file_sha256(HERE / "Containerfile"),
        "aslr_chain_inputs": {
            "rebase_profile_sha256": file_sha256(HERE / "rebase_profile.json"),
            "rebase_fixture_sha256": file_sha256(ROOT / "lab" / "rebase_app.php"),
            "verifier_sha256": file_sha256(HERE / "verify_aslr_chain.py"),
        },
        "versions": versions,
        "host_yama_ptrace_scope": ptrace_scope,
        "packages": package_nevra(
            container,
            ["php-cli", "php-fpm", "php-common", "glibc", "glibc-common", "binutils", "python"],
        ),
        "rpm_verify": {
            "returncode": verify.returncode,
            "stdout": verify.stdout,
            "stderr": verify.stderr,
        },
        "binaries": {
            path: {
                "sha256": sha256_in_container(container, path),
                "build_id": build_id(container, path),
            }
            for path in binaries
        },
        "libpthread_system_relocation_offset": hex(
            relocation_offset(container, "/lib64/libpthread-2.17.so", "__libc_system")
        ),
        "libpthread_system_relocation_lines": relocation_lines,
    }


def write_evidence(evidence_dir: Path, manifest: dict[str, object], results: list[dict[str, object]]) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = evidence_dir / "manifest.json"
    results_path = evidence_dir / "results.json"
    log_path = evidence_dir / "run.log"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    results_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "PHP 5.4 SPL ArrayObject UAF reproduction",
        f"captured_at={manifest['captured_at']}",
    ]
    for result in results:
        lines.extend(
            [
                "",
                f"case={result['case']}",
                f"success={str(result['success']).lower()}",
                f"payload_sha256={result.get('payload_sha256', result.get('trigger_payload_sha256', '-'))}",
                f"marker_created={str(result.get('marker_created', False)).lower()}",
            ]
        )
        if result["case"] in ("fpm-rce", "aslr-rce"):
            lines.append(f"workers_exited={result.get('workers_exited')}")
            lines.append(f"replacement_workers={result.get('replacement_workers')}")
        else:
            lines.append(f"podman_exec_returncode={result.get('podman_exec_returncode')}")
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    checksum_file = evidence_dir / "SHA256SUMS"
    checksum_paths = sorted(
        path for path in evidence_dir.rglob("*") if path.is_file() and path != checksum_file
    )
    checksum_lines = [
        f"{file_sha256(path)}  {path.relative_to(evidence_dir).as_posix()}" for path in checksum_paths
    ]
    checksum_file.write_text("\n".join(checksum_lines) + "\n", encoding="ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--build", action="store_true", help="build the pinned lab image first")
    parser.add_argument("--evidence", type=Path, default=ROOT / "evidence")
    parser.add_argument("--keep-container", action="store_true")
    args = parser.parse_args()

    if args.build:
        build_image(args.image)

    token = secrets.token_hex(4)
    container = token
    run_dir = Path(tempfile.mkdtemp(prefix=f"{token}-", dir="/tmp")).resolve()
    subprocess.run(
        [
            "podman", "run", "-d", "--name", container, "--arch", "amd64",
            "--security-opt", "seccomp=unconfined",
            "--volume", f"{run_dir}:/x:Z", args.image,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        evidence_dir = args.evidence.resolve()
        chain_dir = evidence_dir / "aslr-chain"
        if chain_dir.exists():
            if chain_dir.parent != evidence_dir or chain_dir.name != "aslr-chain":
                raise RuntimeError(f"unexpected ASLR evidence path: {chain_dir}")
            shutil.rmtree(chain_dir)
        manifest = collect_environment(container, args.image)
        results = [
            run_cgi_case(
                container=container,
                run_dir=run_dir,
                php_cgi="/usr/bin/php-cgi",
                expectation="rce",
            ),
            run_cgi_case(
                container=container,
                run_dir=run_dir,
                php_cgi="/usr/bin/php-cgi",
                expectation="invalid-handler",
            ),
            run_cgi_case(
                container=container,
                run_dir=run_dir,
                php_cgi="/opt/php-5.4.44/bin/php-cgi",
                expectation="patched",
            ),
            run_fpm_case(container=container, run_dir=run_dir),
            run_aslr_case(container=container, run_dir=run_dir, artifact_dir=chain_dir),
        ]
        write_evidence(evidence_dir, manifest, results)
        print(json.dumps({"all_success": all(item["success"] for item in results), "results": results}, indent=2))
        return 0 if all(item["success"] for item in results) else 1
    finally:
        if not args.keep_container:
            subprocess.run(
                ["podman", "rm", "--force", container],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        resolved = run_dir.resolve()
        if resolved.parent == Path("/tmp") and resolved.name.startswith(token + "-"):
            shutil.rmtree(resolved, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
