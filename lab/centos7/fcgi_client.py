#!/usr/bin/env python
"""Small Python 2/3 FastCGI client used only inside the lab container."""
from __future__ import print_function

import argparse
import socket
import struct
import sys


def record(record_type, request_id, content=b""):
    padding = (8 - len(content) % 8) % 8
    return struct.pack("!BBHHBB", 1, record_type, request_id, len(content), padding, 0) + content + b"\0" * padding


def encoded_length(length):
    return struct.pack("!B", length) if length < 128 else struct.pack("!I", length | 0x80000000)


def name_value(name, value):
    return encoded_length(len(name)) + encoded_length(len(value)) + name + value


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise socket.error("unexpected EOF")
        data += chunk
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("script")
    parser.add_argument("bodyfile")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    with open(args.bodyfile, "rb") as handle:
        body = handle.read()

    params = {
        "SCRIPT_FILENAME": args.script,
        "REQUEST_METHOD": "POST",
        "CONTENT_TYPE": "application/octet-stream",
        "CONTENT_LENGTH": str(len(body)),
        "SERVER_PROTOCOL": "HTTP/1.1",
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REMOTE_ADDR": "127.0.0.1",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "DOCUMENT_ROOT": "/opt/php54-uaf",
        "REQUEST_URI": "/vuln_app.php",
    }
    blob = b"".join(name_value(k.encode("ascii"), v.encode("ascii")) for k, v in params.items())

    stdout = b""
    stderr = b""
    reset = False
    sock = socket.create_connection((args.host, args.port), args.timeout)
    sock.settimeout(args.timeout)
    try:
        sock.sendall(record(1, 1, struct.pack("!HBxxxxx", 1, 0)))
        sock.sendall(record(4, 1, blob))
        sock.sendall(record(4, 1))
        sock.sendall(record(5, 1, body))
        sock.sendall(record(5, 1))

        while True:
            header = recv_exact(sock, 8)
            _, record_type, _, content_length, padding_length, _ = struct.unpack("!BBHHBB", header)
            content = recv_exact(sock, content_length) if content_length else b""
            if padding_length:
                recv_exact(sock, padding_length)
            if record_type == 6:
                stdout += content
            elif record_type == 7:
                stderr += content
            elif record_type == 3:
                break
    except socket.error as exc:
        reset = True
        print("transport=%s" % exc, file=sys.stderr)
    finally:
        sock.close()

    if stdout:
        sys.stdout.write(stdout.decode("latin1"))
    if stderr:
        print("fastcgi_stderr=" + stderr.decode("latin1", "replace"), file=sys.stderr)
    return 2 if reset else 0


if __name__ == "__main__":
    sys.exit(main())
