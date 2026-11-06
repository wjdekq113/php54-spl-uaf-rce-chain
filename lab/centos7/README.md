# Pinned CentOS 7 native reproduction lab

This lab combines two runtimes on the same frozen CentOS 7.9.2009/glibc
2.17-317 base:

- vulnerable vendor `php-cli/php-fpm-5.4.16-48.el7`;
- upstream-fixed PHP 5.4.44 CGI built from the official hash-pinned source.

Only the frozen CentOS 7 `os` repository is enabled.  Enabling `updates` changes
the glibc patch level and invalidates the recorded heap, symbol, Build ID, and
GOT profile.  No host port is published; FastCGI requests originate inside the
disposable container.

## Automated run

From the repository root:

```bash
python3 lab/centos7/reproduce.py --build --evidence evidence
```

The runner:

1. builds `lab/centos7/Containerfile` for amd64;
2. starts a disposable container with a temporary directory mounted at `/x`;
3. records image, package, binary, relocation, and host-tool identities;
4. runs direct vulnerable CGI, invalid-handler CGI, patched CGI, and direct FPM
   controls;
5. starts a separate single-worker FPM pool and runs the complete heap
   leak -> arbitrary read -> ASLR rebase -> RCE case;
6. writes the top-level evidence and `evidence/aslr-chain/` artifacts;
7. hashes every evidence file and removes the container and temporary directory.

## Complete ASLR case

`verify_aslr_chain.py` is intentionally separate from the process-memory helpers.
It never calls the `mapping_bases()` or `read_qword()` helpers and never opens
`/proc/<pid>/maps` or `/proc/<pid>/mem`.

Its runtime address inputs are:

- the decimal pointer returned by the 101-byte heap-leak body;
- bytes returned by successive 176-byte arbitrary-read bodies.

The static side of the calculation comes from `rebase_profile.json`, which pins
all four binary hashes and Build IDs plus the exact symbol/relocation offsets.
The state machine verifies PHP, libc, the dynamic loader, and libpthread through
both ELF magic and Build ID before reading and comparing the system GOT slot.

The pool uses `fpm-rebase.conf` with exactly one worker.  This keeps dependent
heap reads in one address space.  The final trigger kills that worker and FPM
creates a replacement; both PIDs are recorded as execution evidence.

See ../../ASLR_CHAIN.md for the complete address arithmetic.

## Direct mechanism controls

The direct CGI/FPM scripts obtain container PIDs from
`podman top hpid,pid,args`; they do not scan unrelated host processes.  These
controls read only the selected container process mappings and GOT slot.  They
proceed only when the observed slot value equals the computed libc `system()`
address.

Those `/proc` reads are independent control instrumentation.  Their outputs are
not used by `verify_aslr_chain.py`.

## Case-specific commands

Normally use the integrated runner.  For debugging an already-running lab
container whose host directory is mounted at `/x`:

```bash
python3 lab/centos7/verify_php_cgi.py \
  --container CONTAINER --run-dir HOST_RUN_DIR --expect rce

python3 lab/centos7/verify_php_cgi.py \
  --container CONTAINER --run-dir HOST_RUN_DIR --expect invalid-handler

python3 lab/centos7/verify_php_cgi.py \
  --container CONTAINER --run-dir HOST_RUN_DIR \
  --php-cgi /opt/php-5.4.44/bin/php-cgi --expect patched

python3 lab/centos7/verify_php_fpm.py \
  --container CONTAINER --run-dir HOST_RUN_DIR
```

`HOST_RUN_DIR` must be the absolute directory mounted at `/x`.  The complete
ASLR case is exposed as `run_case()` and is driven by `reproduce.py` so its
artifacts are included in the evidence checksum set.

## Patched control source

The image downloads:

```text
https://museum.php.net/php5/php-5.4.44.tar.gz
sha256 1799998e48da3d8f34722840628e18789e26ea21741d4e498ade6749b3266602
```

The value is published in the official PHP 5.4.44 release metadata.  The source
is configured as a minimal CGI build with SPL, Date, and standard support.
