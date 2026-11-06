# Lab safety and reporting

This repository contains an executable reproducer for a historical memory
corruption vulnerability. The supplied container does not publish a host port.
Run it only as an isolated, disposable local lab.

## Lab boundaries

- The reproducer supports Linux amd64 only.
- The harness creates a short random marker under a temporary bind mount and
  removes it after each case.
- PHP-FPM runs as root inside the disposable Podman container so the seven-byte
  marker can be written to the temporary `/x` mount without host UID assumptions.
- `seccomp=unconfined` is used for the direct process-inspection controls. Do not
  reuse the container as a service image.
- The complete `aslr-rce` case derives addresses only from the heap leak and
  arbitrary-read responses; it does not read process maps or memory through
  `/proc`.
- The auxiliary direct CGI/FPM controls do inspect only the selected disposable
  container process through `/proc` to cross-check the same GOT dispatch.
- No container port is published. The FastCGI client runs inside the container.

## Reporting repository issues

Use the repository's private security-reporting channel, if enabled, for a new
issue that affects currently supported PHP versions or creates an unexpected
escape from the documented container boundary. Ordinary reproducibility and
documentation bugs may be filed as regular issues.
