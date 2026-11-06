# Sources and provenance

This repository is an independent reconstruction and lab validation of a
historical PHP vulnerability. It does not include PHP source code or vendor
binaries.

## Direct vulnerability lineage

| Item | Role in this repository |
|---|---|
| [PHP Bug #70155](https://bugs.php.net/bug.php?id=70155) | Earlier report of the SPL `ArrayObject` reference-lifetime issue; treated as a duplicate of #70166. |
| [PHP Bug #70166](https://bugs.php.net/bug.php?id=70166) | Source of the `ArrayObject`/`DateInterval` arbitrary-read and final-dispatch trigger. Reported by Taoguang Chen. |
| [PHP Bug #70168](https://bugs.php.net/bug.php?id=70168) | Source of the `SplObjectStorage` pointer-leak bootstrap used before the #70166 read primitive. |
| [Full Disclosure post](https://seclists.org/fulldisclosure/2015/Aug/17) | Original public technical description and affected upstream versions. |
| [`7381b6accc5559b2de039af3a22f6ec1003b03b3`](https://github.com/php/php-src/commit/7381b6accc5559b2de039af3a22f6ec1003b03b3) | Direct upstream fix for #70166. It protects `pflags`, `intern->array`, and `pmembers` through the unserialize destructor list. |
| [`c2e197e4efc663ca55f393bf0e799848842286f3`](https://github.com/php/php-src/commit/c2e197e4efc663ca55f393bf0e799848842286f3) | Direct upstream fix for the #70168 `SplObjectStorage` bootstrap vector. |
| [CVE-2015-6831 assignment discussion](https://www.openwall.com/lists/oss-security/2015/09/08/7) | Maps #70155/#70166/#70168/#70169 to the shared CVE. |

The complete chain combines #70168 for the first heap pointer with #70166 for
arbitrary read and code execution. `DateInterval` is part of the #70166 trigger;
this is not the older, separate DateInterval vulnerability CVE-2015-0273.

## Adjacent vulnerability not used by this chain

| Item | Distinction |
|---|---|
| [PHP Bug #70068](https://bugs.php.net/bug.php?id=70068), CVE-2015-6832 | Separate `ArrayObject` items dangling-pointer vector. Fixed by [`b7fa67742cd8d2b0ca0c0273b157f6ffee9ad6e2`](https://github.com/php/php-src/commit/b7fa67742cd8d2b0ca0c0273b157f6ffee9ad6e2). |

## Version and distribution evidence

- Upstream fixed releases: PHP 5.4.44, 5.5.28, and 5.6.12.
- [PHP 5.4.44 release announcement](https://www.php.net/releases/5_4_44.php)
- [PHP 5.4.44 release metadata](https://www.php.net/releases/index.php?serialize=1&version=5.4.44), including the official source archive SHA-256.
- [Red Hat CVE-2015-6831 data](https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2015-6831.json): base RHEL 7 `php` is listed as `Will not fix`; the later fixed advisory concerns the Software Collections package.

## Repository contribution

The code in this repository implements the 101-byte heap-leak and 176-byte
read/exec builders, exploit-response-only ASLR resolver, pinned lab image,
native CGI/FPM controls, fixed-version control, and evidence capture. The
original researchers and PHP maintainers are credited above; their reports and
commits remain the authoritative sources for the underlying vulnerabilities and
fixes.
