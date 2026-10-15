#!/usr/bin/env python3
"""
FeviconHashGenerator.py - discover favicons and compute Shodan/FOFA-compatible MMH3 hashes.

Usage:
  ./FeviconHashGenerator.py https://www.groupebpce.com
  ./FeviconHashGenerator.py www.groupebpce.com https://www.natixis.com
  ./FeviconHashGenerator.py -i domains.txt -o results.tsv -t 30
  cat subs.txt | ./FeviconHashGenerator.py -f json > out.json
  ./FeviconHashGenerator.py -i domains.txt --all -o results.json
  ./FeviconHashGenerator.py target.com -x http://127.0.0.1:8080 -k

Requirements: Python 3.7+ and curl (optional: `pip install mmh3` for a faster hash)
"""

import argparse
import base64
import csv
import hashlib
import html.parser
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, unquote, unquote_to_bytes

VERSION = "2.0"
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
MAX_HTML_BYTES = 3 * 1024 * 1024
MAX_ICON_BYTES = 8 * 1024 * 1024
META_MARK = "__CURL_META__"
FALLBACK_PATHS = ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png")
TRANSIENT_CURL_RC = {35, 52, 55, 56}  # TLS handshake, empty reply, send/recv failure
FIELDS = [
    "input_url", "final_page_url", "favicon_url", "bytes", "shodan_favicon_hash",
    "content_type", "status", "md5", "sha256", "source", "kind", "error",
]

STOP = threading.Event()


# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #
class Term:
    color = False


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if Term.color else str(s)


def ok(s):    return _c("92", s)
def bad(s):   return _c("91", s)
def warn(s):  return _c("93", s)
def dim(s):   return _c("90", s)
def cyan(s):  return _c("96", s)
def mag(s):   return _c("95", s)
def bold(s):  return _c("1", s)
def plain(s): return str(s)


def term_width():
    try:
        return os.get_terminal_size(sys.stderr.fileno()).columns
    except (OSError, ValueError):
        return 110


def trunc(s, w):
    s = str(s)
    return s if len(s) <= w else (s[: max(w - 1, 0)] + "…")


def fmt_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_time(sec):
    sec = int(sec)
    return f"{sec // 60}m{sec % 60:02d}s" if sec >= 60 else f"{sec}s"


def rule(title):
    w = term_width()
    head = f"── {title} "
    return bold(cyan(head)) + dim("─" * max(w - len(head), 0))


def banner(args, n_targets):
    lines = [
        f"FeviconHashGenerator v{VERSION}",
        "Shodan / FOFA favicon MMH3 pivot tool",
    ]
    inner = max(len(l) for l in lines) + 4
    out = [cyan("╭" + "─" * inner + "╮")]
    for i, l in enumerate(lines):
        txt = l.center(inner)
        out.append(cyan("│") + (bold(txt) if i == 0 else dim(txt)) + cyan("│"))
    out.append(cyan("╰" + "─" * inner + "╯"))
    cfg = (
        f"targets={bold(n_targets)}  threads={bold(args.threads)}  timeout={bold(str(args.timeout) + 's')}  "
        f"retries={bold(args.retries)}  mode={bold('all icons' if args.all else 'first hit')}"
    )
    if args.proxy:
        cfg += f"  proxy={bold(args.proxy)}"
    if args.insecure:
        cfg += f"  {warn('TLS verify OFF')}"
    out.append(dim(" ") + cfg)
    return "\n".join(out)


def render_table(headers, rows, flex, aligns):
    """rows: list of rows; each cell is (text, style_fn). Shrinks flex columns to fit the terminal."""
    n = len(headers)
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(n):
            widths[i] = max(widths[i], len(r[i][0]))
    mins = [max(8, len(h)) for h in headers]
    limit = term_width()
    while sum(widths) + 3 * n + 1 > limit:
        cand = [i for i in flex if widths[i] > mins[i]]
        if not cand:
            break
        j = max(cand, key=lambda i: widths[i])
        widths[j] -= 1

    def line(l, m, r):
        return dim(l + m.join("─" * (w + 2) for w in widths) + r)

    def cell(text, w, align, style):
        t = trunc(text, w)
        t = t.rjust(w) if align == "r" else t.ljust(w)
        return style(t)

    out = [line("┌", "┬", "┐")]
    out.append(dim("│") + dim("│").join(" " + cell(h, widths[i], aligns[i], bold) + " " for i, h in enumerate(headers)) + dim("│"))
    out.append(line("├", "┼", "┤"))
    for r in rows:
        out.append(
            dim("│")
            + dim("│").join(" " + cell(r[i][0], widths[i], aligns[i], r[i][1]) + " " for i in range(n))
            + dim("│")
        )
    out.append(line("└", "┴", "┘"))
    return "\n".join(out)


class Dash:
    """Thread-safe live progress bar + per-result lines (all on stderr)."""

    def __init__(self, total, quiet):
        self.total = total
        self.done = self.ok = self.fail = 0
        self.start = time.time()
        self.quiet = quiet
        self.live = (not quiet) and sys.stderr.isatty()
        self.lock = threading.RLock()

    def _bar(self):
        elapsed = max(time.time() - self.start, 1e-6)
        rate = self.done / elapsed
        eta = (self.total - self.done) / rate if rate > 0 else 0
        width = 24
        filled = int(width * self.done / self.total) if self.total else width
        bar = "█" * filled + "░" * (width - filled)
        pct = int(100 * self.done / self.total) if self.total else 100
        return (
            f" {cyan(bar)} {self.done}/{self.total} {pct:3d}%  "
            f"{ok('✔ ' + str(self.ok))}  {bad('✖ ' + str(self.fail))}  "
            f"{dim(f'{rate:.1f}/s  ETA {fmt_time(eta)}')}"
        )

    def emit(self, line=None):
        if self.quiet:
            return
        with self.lock:
            if self.live:
                sys.stderr.write("\r\033[K")
            if line:
                sys.stderr.write(line + "\n")
            if self.live:
                sys.stderr.write(self._bar())
            sys.stderr.flush()

    def record(self, rows):
        with self.lock:
            self.done += 1
            if any(r["status"] == "OK" for r in rows):
                self.ok += 1
            else:
                self.fail += 1
            w = term_width()
            for r in rows:
                self.emit(result_line(r, w))

    def close(self):
        if self.live:
            with self.lock:
                sys.stderr.write("\r\033[K")
                sys.stderr.flush()


def result_line(r, w):
    tgt = trunc(r["input_url"], 40).ljust(40)
    if r["status"] == "OK":
        rest = max(w - 73, 10)
        return (
            f"  {ok('✔')} {tgt} {cyan(r['shodan_favicon_hash'].rjust(11))}  "
            f"{r['kind'].ljust(4)} {fmt_size(r['bytes']).rjust(8)}  {dim(trunc(r['favicon_url'], rest))}"
        )
    msg = f"{r['status']}: {r['error']}" if r["error"] else r["status"]
    return f"  {bad('✖')} {tgt} {bad(trunc(msg, max(w - 47, 10)))}"


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #
def _mmh3_py(data: bytes) -> int:
    """MurmurHash3 x86 32-bit (seed 0), returned as signed int32 like Shodan."""
    length = len(data)
    h = 0
    c1, c2 = 0xCC9E2D51, 0x1B873593
    rounded_end = length & 0xFFFFFFFC

    for i in range(0, rounded_end, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[rounded_end:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k

    h ^= length & 0xFFFFFFFF
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h if h < 0x80000000 else h - 0x100000000


try:  # prefer the C implementation when available
    import mmh3 as _mmh3_lib

    def mmh3_32(data: bytes) -> int:
        return _mmh3_lib.hash(data)
except Exception:  # pragma: no cover
    mmh3_32 = _mmh3_py


def shodan_hash(icon_bytes: bytes) -> int:
    # Shodan: mmh3 over base64 with line breaks every 76 chars (codecs.encode(b, "base64"))
    return mmh3_32(base64.encodebytes(icon_bytes))


# --------------------------------------------------------------------------- #
# Fetching (curl)
# --------------------------------------------------------------------------- #
class Resp:
    __slots__ = ("ok", "body", "url", "status", "ctype", "error")

    def __init__(self, ok=False, body=b"", url="", status="", ctype="", error=""):
        self.ok, self.body, self.url, self.status, self.ctype, self.error = ok, body, url, status, ctype, error


def _fetch_once(url, o, max_bytes):
    cmd = [
        "curl", "-sS", "-L", "--max-time", str(o.timeout),
        "--connect-timeout", str(min(o.timeout, 10)),
        "--max-redirs", "8", "--compressed",
        # never follow into file://, gopher://, dict:// ... (page-controlled URLs reach curl)
        "--proto", "=http,https", "--proto-redir", "=http,https",
        "-A", o.user_agent, "-H", "Accept: */*",
    ]
    if o.insecure:
        cmd.append("-k")
    if o.proxy:
        cmd += ["-x", o.proxy]
    for h in o.header:
        cmd += ["-H", h]
    cmd += ["-w", "\n" + META_MARK + "%{http_code}\t%{url_effective}\t%{content_type}\n", url]

    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return Resp(url=url, error=str(exc)), False

    buf = bytearray()
    over = False
    while True:
        chunk = p.stdout.read(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_bytes + 4096:  # hard cap while streaming, not after the fact
            over = True
            p.kill()
            break
    err = p.stderr.read().decode("utf-8", "replace").strip()
    p.stdout.close()
    p.stderr.close()
    rc = p.wait()

    if over:
        return Resp(url=url, error=f"response too large (>{fmt_size(max_bytes)})"), False

    marker = b"\n" + META_MARK.encode()
    idx = buf.rfind(marker)
    if idx < 0:
        return Resp(url=url, error=err or f"curl exit {rc}"), rc in TRANSIENT_CURL_RC

    body = bytes(buf[:idx])
    meta = bytes(buf[idx + len(marker):]).decode("utf-8", "replace").strip().split("\t")
    status = meta[0] if len(meta) > 0 else ""
    eff = meta[1] if len(meta) > 1 and meta[1] else url
    ctype = meta[2] if len(meta) > 2 else ""

    if rc != 0:
        return Resp(url=eff, status=status, error=err or f"curl exit {rc}"), rc in TRANSIENT_CURL_RC
    if not status.startswith("2"):
        return Resp(url=eff, status=status, error=f"HTTP {status or 'unknown'}"), False
    return Resp(ok=True, body=body, url=eff, status=status, ctype=ctype), False


def fetch(url, o, max_bytes):
    last = Resp(url=url, error="interrupted")
    for _ in range(o.retries + 1):
        if STOP.is_set():
            return last
        r, transient = _fetch_once(url, o, max_bytes)
        if r.ok or not transient:
            return r
        last = r
    return last


# --------------------------------------------------------------------------- #
# Parsing / validation
# --------------------------------------------------------------------------- #
class IconParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.icons = []  # (priority, order, href)
        self.base = None
        self._n = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base":
            if self.base is None and a.get("href", "").strip():
                self.base = a["href"].strip()
            return
        if tag != "link":
            return
        href = a.get("href", "").strip()
        if not href:
            return
        rel = a.get("rel", "").lower().split()
        if "icon" in rel:                       # "icon" and "shortcut icon"
            prio = 0
        elif "shortcut" in rel:
            prio = 1
        elif "apple-touch-icon" in rel or "apple-touch-icon-precomposed" in rel:
            prio = 2
        else:                                   # mask-icon, preload, etc. are ignored
            return
        self.icons.append((prio, self._n, href))
        self._n += 1


def decode_data_uri(uri):
    m = re.match(r"data:([^,]*),(.*)$", uri, re.S | re.I)
    if not m:
        return None, ""
    meta, payload = m.groups()
    parts = meta.split(";")
    ctype = parts[0] or "text/plain"
    try:
        raw = unquote_to_bytes(payload)
        if any(p.strip().lower() == "base64" for p in parts[1:]):
            raw = raw.strip()
            raw += b"=" * (-len(raw) % 4)
            body = base64.b64decode(raw)
        else:
            body = raw
    except Exception:
        return None, ctype
    if len(body) > MAX_ICON_BYTES:
        return None, ctype
    return body, ctype


def sniff(b: bytes):
    h = b[:16]
    if h[:4] in (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"):
        return "ico"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if h[:3] == b"GIF":
        return "gif"
    if h[:3] == b"\xff\xd8\xff":
        return "jpg"
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return "webp"
    if h[:2] == b"BM":
        return "bmp"
    if b"<svg" in b[:1024].lower():
        return "svg"
    return None


def ctype_kind(ctype):
    ct = (ctype or "").split(";")[0].strip().lower()
    if not ct.startswith("image/"):
        return None
    sub = ct[6:]
    return {"vnd.microsoft.icon": "ico", "x-icon": "ico", "svg+xml": "svg", "jpeg": "jpg"}.get(sub, sub[:4] or None)


def looks_like_html(data: bytes, content_type: str) -> bool:
    if sniff(data):
        return False
    start = data[:512].lstrip().lower()
    return (
        "text/html" in (content_type or "").lower()
        or start.startswith(b"<!doctype html")
        or start.startswith(b"<html")
        or b"<html" in start[:200]
    )


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    return value


# --------------------------------------------------------------------------- #
# Per-target worker
# --------------------------------------------------------------------------- #
def try_icon(url, o):
    """Return (entry|None, error)."""
    if url.lower().startswith("data:"):
        body, ctype = decode_data_uri(url)
        if body is None:
            return None, "invalid data: URI"
        eff = f"data:{ctype or '?'} ({len(body)} bytes)"
    else:
        r = fetch(url, o, MAX_ICON_BYTES)
        if not r.ok:
            return None, r.error
        body, eff, ctype = r.body, r.url, r.ctype
    if not body:
        return None, "empty response"
    if looks_like_html(body, ctype):
        return None, "returned HTML, not an image"
    kind = sniff(body) or ctype_kind(ctype) or "?"
    return {
        "url": eff, "body": body, "ctype": ctype, "kind": kind,
        "hash": shodan_hash(body),
        "md5": hashlib.md5(body).hexdigest(),
        "sha256": hashlib.sha256(body).hexdigest(),
    }, None


def process(target, o):
    def row(**kw):
        d = {k: "" for k in FIELDS}
        d["input_url"] = target
        d.update(kw)
        return d

    if STOP.is_set():
        return [row(status="SKIPPED", error="interrupted")]
    try:
        return _process(target, o, row)
    except Exception as exc:  # never let one target kill the run
        return [row(status="ERROR", error=f"{type(exc).__name__}: {exc}")]


def _process(target, o, row):
    page = fetch(target, o, MAX_HTML_BYTES)
    page_err = page.error
    if not page.ok and target.lower().startswith("https://"):
        alt = fetch("http://" + target[len("https://"):], o, MAX_HTML_BYTES)
        if alt.ok:
            page = alt
    page_url = page.url if page.ok else target

    cands, seen_urls = [], set()

    def add(u, src):
        if u and u not in seen_urls:
            seen_urls.add(u)
            cands.append((u, src))

    if page.ok:
        parser = IconParser()
        try:
            parser.feed(page.body.decode("utf-8", "replace"))
        except Exception:
            pass
        base = urljoin(page_url, parser.base) if parser.base else page_url
        for _, _, href in sorted(parser.icons):
            if href.lower().startswith("data:"):
                add(href, "data-uri")
                continue
            absu = urljoin(base, href)
            if urlparse(absu).scheme in ("http", "https"):
                add(absu, "declared")
    if not o.no_fallback:
        for path in FALLBACK_PATHS:
            add(urljoin(page_url, path), "fallback")

    found, seen_hash, errors = [], set(), []
    note = "" if page.ok else f"page fetch failed ({page_err}); used fallback paths"
    for url, src in cands:
        if STOP.is_set():
            break
        ent, err = try_icon(url, o)
        if err:
            errors.append(f"{trunc(url, 60)}: {err}")
            continue
        if ent["sha256"] in seen_hash:
            continue
        seen_hash.add(ent["sha256"])
        found.append(row(
            final_page_url=page_url, favicon_url=ent["url"], bytes=str(len(ent["body"])),
            shodan_favicon_hash=str(ent["hash"]), content_type=ent["ctype"] or ent["kind"],
            status="OK", md5=ent["md5"], sha256=ent["sha256"], source=src, kind=ent["kind"], error=note,
        ))
        if not o.all:
            break
    if found:
        return found

    if not page.ok:
        return [row(final_page_url=page_url, status="PAGE_ERROR", error=page_err or "page fetch failed")]
    detail = "; ".join(errors[:3]) if errors else "no favicon links and fallbacks disabled"
    return [row(final_page_url=page_url, status="NO_FAVICON", error=detail)]


# --------------------------------------------------------------------------- #
# Reporting / output
# --------------------------------------------------------------------------- #
def queries_for(h):
    return f"http.favicon.hash:{h}", f'icon_hash="{h}"'


def print_report(rows, elapsed, interrupted, o):
    out = sys.stderr
    oks = [r for r in rows if r["status"] == "OK"]
    fails = [r for r in rows if r["status"] != "OK"]

    out.write("\n" + rule("Results") + "\n")
    if rows:
        trows = []
        for i, r in enumerate(rows, 1):
            if r["status"] == "OK":
                trows.append([
                    (str(i), dim), (r["input_url"], plain), (r["shodan_favicon_hash"], cyan),
                    (r["kind"], plain), (fmt_size(r["bytes"]), plain), (r["favicon_url"], dim),
                ])
            else:
                trows.append([
                    (str(i), dim), (r["input_url"], plain), ("—", dim), ("—", dim), ("—", dim),
                    (f"{r['status']}: {r['error']}" if r["error"] else r["status"], bad),
                ])
        out.write(render_table(["#", "Target", "MMH3 hash", "Type", "Size", "Favicon / error"], trows,
                               flex=(1, 5), aligns=["r", "l", "r", "l", "r", "l"]) + "\n")

    # Pivot clusters: same hash across several distinct targets = likely related infrastructure
    groups = {}
    for r in oks:
        groups.setdefault(r["shodan_favicon_hash"], set()).add(r["input_url"])
    clusters = sorted(((h, t) for h, t in groups.items() if len(t) > 1), key=lambda x: -len(x[1]))
    if clusters:
        out.write("\n" + rule("Clusters (same hash on multiple targets)") + "\n")
        for h, t in clusters[:10]:
            names = sorted(t)
            more = f" +{len(names) - 3} more" if len(names) > 3 else ""
            out.write(f"  {cyan(h.rjust(11))}  {mag('×' + str(len(names)))}  "
                      f"{dim(trunc(', '.join(names[:3]) + more, term_width() - 22))}\n")

    if groups:
        out.write("\n" + rule("Search queries") + "\n")
        ordered = sorted(groups.items(), key=lambda x: -len(x[1]))
        for h, _ in ordered[:10]:
            sq, fq = queries_for(h)
            out.write(f"  {cyan(h.rjust(11))}  {dim('shodan')} {sq}   {dim('fofa')} {fq}\n")
        if len(ordered) > 10:
            out.write(dim(f"  … +{len(ordered) - 10} more hashes (see output file)\n"))

    out.write("\n" + rule("Summary") + "\n")
    n_targets = len({r["input_url"] for r in rows})
    out.write(
        f"  targets {bold(n_targets)}   {ok('✔ ' + str(len({r['input_url'] for r in oks})))}   "
        f"{bad('✖ ' + str(len({r['input_url'] for r in fails} - {r['input_url'] for r in oks})))}   "
        f"unique hashes {bold(len(groups))}   elapsed {bold(fmt_time(elapsed))}\n"
    )
    if interrupted:
        out.write(warn("  ! interrupted - partial results\n"))
    out.flush()


def write_rows(rows, fmt, fh):
    if fmt == "json":
        data = []
        for r in rows:
            d = dict(r)
            if r["status"] == "OK":
                d["shodan_query"], d["fofa_query"] = queries_for(r["shodan_favicon_hash"])
            data.append(d)
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
        return
    w = csv.writer(fh, delimiter="\t" if fmt == "tsv" else ",", lineterminator="\n")
    w.writerow(FIELDS)
    for r in rows:
        w.writerow([r[k] for k in FIELDS])


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Discover website favicons and calculate Shodan/FOFA-compatible MMH3 hashes."
    )
    ap.add_argument("targets", nargs="*", help="URLs or hostnames")
    ap.add_argument("-i", "--input", help="File with one URL/hostname per line ('-' for stdin)")
    ap.add_argument("-o", "--output", help="Write results to this file (format from extension or -f)")
    ap.add_argument("-f", "--format", choices=["tsv", "csv", "json"], help="Output format (default: tsv)")
    ap.add_argument("-t", "--threads", type=int, default=10, help="Concurrent targets (default: 10)")
    ap.add_argument("--timeout", type=int, default=20, help="Per-request timeout in seconds (default: 20)")
    ap.add_argument("-r", "--retries", type=int, default=1, help="Retries on transient TLS/reset errors (default: 1)")
    ap.add_argument("-a", "--all", action="store_true", help="Hash every discovered icon, not just the first hit")
    ap.add_argument("--no-fallback", action="store_true", help="Do not probe /favicon.ico, /favicon.png, /apple-touch-icon.png")
    ap.add_argument("-k", "--insecure", action="store_true", help="Allow invalid TLS certificates (curl -k)")
    ap.add_argument("-x", "--proxy", help="Proxy URL passed to curl -x (e.g. http://127.0.0.1:8080)")
    ap.add_argument("-H", "--header", action="append", default=[], help="Extra request header (repeatable)")
    ap.add_argument("--user-agent", default=USER_AGENT, help="Override User-Agent")
    ap.add_argument("-q", "--quiet", action="store_true", help="No dashboard/progress output")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = ap.parse_args()

    Term.color = sys.stderr.isatty() and not args.no_color and "NO_COLOR" not in os.environ

    if not shutil.which("curl"):
        print("[-] curl is required. Install it with: sudo apt install curl", file=sys.stderr)
        return 2
    args.threads = max(1, args.threads)
    args.retries = max(0, args.retries)

    raw = list(args.targets)
    try:
        if args.input == "-" or (not raw and not args.input and not sys.stdin.isatty()):
            raw.extend(sys.stdin.read().splitlines())
        elif args.input:
            with open(args.input, encoding="utf-8", errors="replace") as f:
                raw.extend(f.read().splitlines())
    except OSError as exc:
        print(f"[-] Cannot read input file: {exc}", file=sys.stderr)
        return 2

    targets = [normalize_url(t) for t in raw if t.strip() and not t.lstrip().startswith("#")]
    targets = list(dict.fromkeys(t for t in targets if t))  # dedupe, keep order
    if not targets:
        ap.error("provide URLs/hostnames, use -i domains.txt, or pipe targets via stdin")

    fmt = args.format
    if not fmt:
        ext = os.path.splitext(args.output or "")[1].lower().lstrip(".")
        fmt = ext if ext in ("json", "csv", "tsv") else "tsv"

    if not args.quiet:
        sys.stderr.write(banner(args, len(targets)) + "\n\n")

    dash = Dash(len(targets), args.quiet)
    results = [None] * len(targets)
    start = time.time()
    interrupted = False
    ex = ThreadPoolExecutor(max_workers=min(args.threads, len(targets)))
    futs = {ex.submit(process, t, args): i for i, t in enumerate(targets)}
    try:
        dash.emit()
        for f in as_completed(futs):
            rows = f.result()
            results[futs[f]] = rows
            dash.record(rows)
    except KeyboardInterrupt:
        interrupted = True
        STOP.set()
        for f in futs:
            f.cancel()
    finally:
        ex.shutdown(wait=False)
    dash.close()
    elapsed = time.time() - start

    rows = [r for rs in results if rs for r in rs]
    if not args.quiet:
        print_report(rows, elapsed, interrupted, args)

    if args.output:
        try:
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                write_rows(rows, fmt, f)
            if not args.quiet:
                sys.stderr.write(f"\n  {ok('✔')} wrote {len(rows)} rows to {bold(args.output)} {dim('(' + fmt + ')')}\n")
        except OSError as exc:
            print(f"[-] Cannot write output file: {exc}", file=sys.stderr)
            return 2
    elif not sys.stdout.isatty():
        write_rows(rows, fmt, sys.stdout)
    elif not args.quiet:
        sys.stderr.write(dim("\n  tip: -o results.tsv|csv|json to save, or pipe stdout for machine-readable output\n"))

    if interrupted:
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(130)
    return 0 if any(r["status"] == "OK" for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
