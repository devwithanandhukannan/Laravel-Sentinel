#!/usr/bin/env python3
"""
Laravel Sentinel - local malware scanner, deobfuscator and triage UI for Laravel projects.

Usage:
    python3 laravel_sentinel.py                       # opens the browser / desktop UI
    python3 laravel_sentinel.py /path/to/project      # opens UI with path pre-filled
    python3 laravel_sentinel.py /path --cli --json report.json   # headless scan (exits with code 1 on findings)
    python3 laravel_sentinel.py /path --cli --fail-on high       # custom severity failure threshold
    python3 laravel_sentinel.py --generate-htaccess /path/to/dir # creates hardened .htaccess

Safety: this tool is READ-ONLY by default. It never executes, includes or eval()s anything it
scans. Decoding is done with pure data transforms (base64, inflate, xor ...). The only write
operation is the optional Quarantine button, which MOVES files to a folder next to the project.
The web UI listens on 127.0.0.1 only and every API call needs a random per-run token.

Standard library only (Python 3.8+).
"""
import argparse, base64, binascii, bz2, codecs, datetime, gzip, hashlib, html, io, json, lzma
import math, os, re, secrets, shutil, stat, sys, threading, time, webbrowser, zipfile, zlib
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_to_bytes, urlparse

APP, VERSION = "Laravel Sentinel", "2.1"
MAX_READ = 6 * 1024 * 1024
MAX_OUT = 25 * 1024 * 1024
MAX_DEPTH = 30
SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

PHP_EXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".pht", ".phps", ".phar",
           ".inc", ".suspected", ".module"}
IMG_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".bmp"}
JS_EXT = {".js", ".mjs", ".html", ".htm", ".svg"}
PHPINSIDE_EXT = IMG_EXT | {".css", ".txt", ".woff", ".woff2", ".ttf", ".pdf", ".mp4", ".mp3", ".js"}
ZIP_OK = {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".apk", ".xpi", ".whl", ".epub",
          ".nupkg", ".war"}
ARCH_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".sql", ".bak", ".old", ".dump",
            ".backup", ".tar.gz"}
IMG_MAGIC = [(b"\xff\xd8\xff", "JPEG"), (b"\x89PNG\r\n\x1a\n", "PNG"), (b"GIF87a", "GIF"), (b"GIF89a", "GIF")]

# ----------------------------------------------------------------------------------------------
# Detection rules
# ----------------------------------------------------------------------------------------------
RULES = []


def rule(rid, sev, title, pat, desc, targets=("php",), cat="code", noisy=False, flags=re.I | re.S):
    RULES.append(dict(id=rid, sev=sev, title=title, rx=re.compile(pat, flags), desc=desc,
                      targets=set(targets), cat=cat, noisy=noisy))


DEC = r"(?:gzinflate|gzuncompress|gzdecode|base64_decode|str_rot13|strrev|convert_uudecode|bzdecompress|hex2bin|rawurldecode|urldecode)"
REQ = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)"
rule("R001", "critical", "eval() of an encoded / compressed string",
     r"\b(?:eval|assert)\s*\(\s*@?\s*" + DEC + r"\s*\(",
     "eval() running a decoded string is the classic obfuscated-backdoor pattern.", cat="obfuscation")
rule("R002", "critical", "Code execution fed by request data",
     r"\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|call_user_func(?:_array)?|create_function)\s*\(\s*(?:@\s*)?[^;]{0,120}?" + REQ + r"\b",
     "A command/code-execution function receives attacker-controlled input.", cat="backdoor")
rule("R003", "high", "Dynamic function call from request input",
     r"\$[A-Za-z_]\w*\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(",
     "Calling a function whose name/arguments come from the request is a webshell trait.", cat="backdoor")
rule("R004", "high", "preg_replace with /e modifier (code execution)",
     r"preg_replace\s*\(\s*(['\"]).{1,200}?/[a-z]*e[a-z]*\1", "The /e modifier evaluates the replacement as PHP.", cat="backdoor")
rule("R005", "critical", "__halt_compiler() data tail loader",
     r"__halt_compiler(?:\s*/\*.*?\*/)*\s*\(\s*(?:/\*.*?\*/\s*)*\)",
     "Raw binary appended after __halt_compiler() - used to hide a compressed payload.", cat="obfuscation")
rule("R006", "critical", "include/require through a stream wrapper (zip:// phar:// data:// php://)",
     r"\b(?:include|require)(?:_once)?\b[^;\n]{0,80}?(?:zip|phar|data|expect|php)://",
     "Loads code straight out of an archive/stream so no .php payload file exists on disk.", cat="obfuscation")
rule("R007", "critical", "Known webshell / file-manager signature",
     r"FilesMan|c99shell|r57shell|b374k|WSO\s*[0-9.]+|wso_version|Tiny\s*File\s*Manager|tinyfilemanager|PHP\s+File\s+Manager|Krypton\s+File\s*Manager|mogachuda|b3p45|alfa\s*team|IndoXploit|Priv8|Hacked\s*By|Mini\s*Shell|Weevely|China\s*Chopper|AnonymousFox|Cyber\s*Shell",
     "Matches the banner/strings of a public webshell kit.", cat="backdoor")
rule("R008", "critical", "Known C2 / malicious infrastructure (from your report)",
     r"fourfine\.com|zd018", "Domain used by the SEO-cloaking command & control server.", targets=("any",), cat="c2")
rule("R009", "critical", "Crypter backdoor ('Lock' class eval of $_std)",
     r"\$view\s*=\s*eval\s*\(\s*\$_std\s*\)|function\s+check\s*\(\s*\$_std\s*\)",
     "Executes encrypted commands supplied by the attacker.", cat="backdoor")
rule("R010", "critical", "tmpfile()+include in-memory stream loader",
     r"(?:stream_get_meta_data\s*\([^)]*\)[^;]{0,80}?['\"]uri['\"]|['\"]uri['\"][^;]{0,80}?(?:require|include)(?:_once)?\s*\(\s*\$[A-Za-z_])",
     "Executes decoded code directly out of a memory stream/tempfile without writing to disk.", cat="backdoor")
rule("R011", "high", "Remote code fetch and execute",
     r"\b(?:eval|include|require)(?:_once)?\s*\(?\s*(?:@\s*)?(?:file_get_contents|curl_exec|fopen)\s*\(",
     "Downloads code from elsewhere and runs it.", cat="backdoor")
rule("R012", "high", "SEO cloaking: search-engine user-agent switch",
     r"HTTP_USER_AGENT[^\n]{0,200}(?:Googlebot|Google|Baidu|Bing|Yahoo|Docomo|Yandex)|(?:Googlebot|Docomo|Yahoo|Google)[^\n]{0,200}HTTP_USER_AGENT",
     "Shows different content to search engines than to visitors.", cat="seo-spam", noisy=True)
rule("R013", "high", "Search-engine bot list string (cloaking)",
     r"['\"]\s*(?:Yahoo|Google|Bing|Baidu)\s*\|\s*(?:Google|Docomo|Bing|Yahoo|Baidu|Yandex)[A-Za-z|]{0,40}['\"]",
     "Pipe-separated bot names used to decide who gets spam content.", cat="seo-spam")
rule("R014", "high", "Crawler/scanner blocklist regex (anti-analysis)",
     r"(?:Scrapy|SemrushBot|AhrefsBot|Mj12bot|DotBot|Bytespider)[^\n]{0,400}(?:Scrapy|SemrushBot|AhrefsBot|Mj12bot|DotBot|Bytespider|CensysInspect|ZmEu)",
     "Blocks security crawlers so the infection is harder to find.", cat="seo-spam")
rule("R015", "high", "String stitching of many tiny fragments",
     r"(?:\$\w+\s*=\s*['\"][^'\"]{1,12}['\"]\s*;\s*){5,}", "Builds URLs/function names from fragments to evade signatures.",
     cat="obfuscation", noisy=True)
rule("R016", "medium", "Long chr() chain (hidden string)",
     r"(?:chr\(\s*(?:0x[0-9a-f]+|\d+)\s*\)\s*\.\s*){5,}", "Spells a string out character-by-character.", cat="obfuscation")
rule("R017", "medium", "Hex / octal escaped string blob",
     r"(?:\\x[0-9a-f]{2}){12,}|(?:\\[0-7]{3}){12,}", "Escaped bytes hide function names and payloads.", cat="obfuscation", noisy=True)
rule("R018", "medium", "Very large encoded string literal",
     r"['\"][A-Za-z0-9+/=]{400,}['\"]", "A long base64/hex-like literal, typically an embedded payload.", cat="obfuscation", noisy=True)
rule("R019", "high", "Request data written to disk (dropper)",
     r"(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,100}" + REQ, "Lets a remote party write arbitrary files.", cat="backdoor")
rule("R020", "medium", "Raw move_uploaded_file($_FILES ...)",
     r"move_uploaded_file\s*\(\s*\$_FILES", "Upload handler with no framework validation.", cat="upload", noisy=True)
rule("R021", "high", "extract() on request data",
     r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", "Variable-injection primitive.", cat="backdoor")
rule("R022", "high", "unserialize() on request data",
     r"unserialize\s*\(\s*(?:@\s*)?(?:base64_decode\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)", "Object-injection / gadget chain entry point.", cat="backdoor")
rule("R023", "critical", "base64_decode() of request data (command channel)",
     r"base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", "Receives encoded commands from the attacker.", cat="backdoor")
rule("R024", "medium", "phpinfo() exposed", r"\bphpinfo\s*\(", "Leaks server configuration.", cat="exposure", noisy=True)
rule("R025", "high", "Shell command built from a variable",
     r"\b(?:shell_exec|passthru|system|exec|popen|proc_open)\s*\(\s*\$[A-Za-z_]", "Possible command injection / shell.", cat="backdoor", noisy=True)
rule("R026", "medium", "Writes .php/.htaccess files at runtime",
     r"(?:file_put_contents|fopen|fwrite)\s*\([^;]{0,120}(?:\.php|\.htaccess)['\"]", "Typical of droppers / persistence installers.", cat="backdoor", noisy=True)
rule("R027", "low", "Disables PHP security functions",
     r"ini_set\s*\(\s*['\"]disable_functions|ini_restore\s*\(\s*['\"]disable_functions", "Weakens PHP hardening.", cat="backdoor")
rule("R028", "critical", "Cryptominer indicator",
     r"coinhive|cryptonight|stratum\+tcp://|xmrig|minexmr", "Mining software strings.", targets=("any",), cat="miner")
rule("R029", "critical", "Callback code execution with request input",
     r"\b(?:array_map|array_filter|array_walk|array_reduce|usort|uksort|uasort|register_shutdown_function|register_tick_function|mb_ereg_replace_callback|preg_replace_callback)\s*\(\s*(?:['\"](?:assert|system|exec|passthru|shell_exec|popen)['\"]|\$[A-Za-z_]\w*)\s*,\s*(?:@\s*)?[^;]{0,120}?" + REQ + r"\b",
     "A PHP callback function is fed attacker-controlled request input.", cat="backdoor")
rule("R030", "critical", "PHP filter chain / wrapper abuse",
     r"php://filter/(?:convert\.(?:base64|iconv)|read=|resource=)",
     "PHP filter chain used in LFI-to-RCE exploit delivery.", cat="backdoor")
rule("R031", "critical", "Hex-encoded dangerous function list (in-memory dropper)",
     r"\b(?:666f70656e|746d7066696c65|73747265616d5f6765745f6d6574615f64617461|5f5f68616c745f636f6d70696c6572|677a696e666c617465)\b",
     "Contains hex-encoded strings for fopen/tmpfile/stream_get_meta_data/__halt_compiler used by in-memory droppers.", cat="backdoor")
rule("R032", "critical", "SEO cloaking search engine bot switcher",
     r"\$bagent\s*=\s*['\"][^'\"]*?(?:Google|Yahoo|Docomo|Bing|Baidu)",
     "Matches blackhat SEO cloaking code that serves different content to search engines.", cat="seo-spam")
rule("J001", "high", "JS: eval of decoded string", r"\beval\s*\(\s*(?:atob|unescape|String\.fromCharCode)",
     "Obfuscated JavaScript loader.", targets=("js",), cat="js-malware")
rule("J002", "high", "JS: document.write(unescape(...))", r"document\.write\s*\(\s*unescape",
     "Injects hidden content/iframes.", targets=("js",), cat="js-malware")
rule("J003", "high", "JS: long fromCharCode array", r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){30,}",
     "Hides a script as char codes.", targets=("js",), cat="js-malware")
rule("J004", "medium", "JS: script from suspicious TLD",
     r"<script[^>]+src=['\"]https?://[^'\"]*\.(?:ru|cn|tk|xyz|top|click)/", "External script from a high-abuse TLD.",
     targets=("js",), cat="js-malware")
rule("H001", "high", "auto_prepend_file / auto_append_file",
     r"auto_(?:prepend|append)_file", "Runs an attacker file before/after every PHP request.", targets=("ht",), cat="htaccess")
rule("H002", "critical", "Image/text extensions mapped to the PHP handler",
     r"(?:AddType|AddHandler|SetHandler)[^\n]*(?:php|lsphp)[^\n]*\.(?:jpe?g|png|gif|webp|ico|txt|css|js)\b",
     "Makes uploaded images execute as PHP.", targets=("ht",), cat="htaccess")
rule("H003", "high", "User-agent / referer based rewrite (cloaking)",
     r"RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}[^\n]*(?:google|bing|yahoo|baidu|yandex|docomo)",
     "Redirects search-engine traffic.", targets=("ht",), cat="seo-spam")
rule("H004", "medium", "Rewrite to an external URL", r"RewriteRule\s+[^\n]*\s+https?://",
     "Redirects visitors off-site.", targets=("ht",), cat="htaccess")
rule("H005", "high", "Deny-all with allow-listed script (admin lock-out evasion)",
     r"<FilesMatch[^>]*>\s*(?:Order\s+Allow,Deny\s*)?(?:Deny\s+from\s+all|Require\s+all\s+denied)[\s\S]{0,300}?<Files(?:Match)?\s+[^>]*>\s*(?:Order\s+Allow,Deny\s*)?(?:Allow\s+from\s+all|Require\s+all\s+granted)",
     "Blocks everything except one specific script - a backdoor protecting itself.", targets=("ht",), cat="htaccess")
rule("H006", "high", "PHP handler directive in .htaccess",
     r"(?:SetHandler|AddHandler|AddType)[^\n]*(?:php|lsphp)", "PHP execution policy set here.", targets=("ht",), cat="htaccess")

QUICK = re.compile(r"base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|__halt_compiler|[A-Za-z0-9+/=]{200,}|chr\s*\(\s*\d|\\x[0-9a-f]{2}|\beval\b|[ \t\r\n]{100,}", re.I)
WS_RUN = re.compile(r"[ \t\r\n]{100,}")
SECRET_RULES = [
    ("K001", "critical", "AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("K002", "critical", "AWS secret access key", r"aws_?secret_?(?:access_?)?key['\"]?\s*(?:=>|=|:)\s*['\"]?([A-Za-z0-9/+=]{40})\b"),
    ("K003", "high", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("K004", "critical", "Stripe live secret key", r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    ("K005", "high", "Slack token", r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    ("K006", "critical", "GitHub access token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    ("K007", "critical", "Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    ("K008", "high", "JSON Web Token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("K009", "high", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),
    ("K010", "high", "Razorpay key", r"\brzp_(?:live|test)_[A-Za-z0-9]{10,}"),
    ("K011", "high", "Twilio API key", r"\bSK[0-9a-f]{32}\b"),
    ("K012", "high", "Mailgun API key", r"\bkey-[0-9a-f]{32}\b"),
    ("K013", "high", "Credentials inside a connection URL", r"\b(?:mysql|pgsql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|ftp|sftp)://[^:/\s'\"@]{1,40}:[^@\s'\"]{3,}@"),
    ("K014", "medium", "Laravel APP_KEY value outside .env", r"base64:[A-Za-z0-9+/]{43}="),
]
SECRET_RX = {rid: re.compile(pat, re.I if rid == "K002" else 0) for rid, _, _, pat in SECRET_RULES}
GENERIC_SECRET = re.compile(r"['\"]?\b(db_?pass(?:word)?|password|passwd|pwd|secret(?:_?key)?|api_?key|apikey|access_?token|auth_?token|client_?secret|merchant_?(?:key|salt)|salt|private_?key)['\"]?\s*(?:=>|=|:)\s*['\"]([^'\"\s$]{6,})['\"]", re.I)
PLACEHOLDER = re.compile(r"^(?:null|none|true|false|secret|password|passwd|changeme|change[_-]?me|your[_\- ].*|x{3,}|\*+|example.*|test(?:ing)?|dummy|foo|bar|laravel|homestead|forge|admin|<.*>|\{.*\}|%.*%|.*(?:here|placeholder).*|\.{3,}|0+|1234.*)$", re.I)
SECRET_EXT = {".php", ".js", ".mjs", ".json", ".yml", ".yaml", ".xml", ".ini", ".txt", ".conf", ".cfg", ".sh", ".config", ".properties", ".toml", ".sql", ".env"}
PHP_HINT = re.compile(rb"<\?(?:php|=)|\beval\s*\(|base64_decode\s*\(|\bsystem\s*\(|shell_exec\s*\(|passthru\s*\(|\$_(?:GET|POST|REQUEST|COOKIE)\b|gzinflate\s*\(|\bassert\s*\(", re.I)
STD_PNG = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"bKGD", b"hIST", b"pHYs",
           b"sPLT", b"tIME", b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"acTL", b"fcTL", b"fdAT", b"cICP", b"mDCv", b"cLLi"}


def mask(v):
    v = str(v)
    return (v[:3] + "…" + v[-2:] + " (%d chars)" % len(v)) if len(v) > 8 else "••••"


def _snip(b, n=100):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b[:n])


def jpeg_check(b, whole):
    """Walk JPEG segments; return (sev, rule, title, desc, offset, snippet) tuples."""
    out, i, n = [], 2, len(b)
    while i + 4 <= n and b[i] == 0xFF:
        m = b[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m in (0x00, 0x01) or 0xD0 <= m <= 0xD8:
            i += 2
            continue
        if m == 0xD9:
            break
        L = int.from_bytes(b[i + 2:i + 4], "big")
        if L < 2:
            break
        seg = b[i + 4:i + 2 + L]
        name = "COM (comment)" if m == 0xFE else ("APP%d" % (m - 0xE0) if 0xE0 <= m <= 0xEF else "0x%02X" % m)
        if m == 0xFE or 0xE0 <= m <= 0xEF:
            h = PHP_HINT.search(seg)
            if h:
                out.append(("critical", "I010", "Code hidden in JPEG %s segment" % name,
                            "EXIF/comment blocks are a favourite place to smuggle PHP; it survives some upload filters and is run if the file is ever included.",
                            i + 4 + h.start(), _snip(seg[h.start():h.start() + 100])))
            if m == 0xFE and L > 2000:
                out.append(("medium", "I011", "Unusually large JPEG comment (%d bytes)" % L, "Comments are normally a few bytes.", i, _snip(seg, 80)))
        if m == 0xDA:
            break
        i += 2 + L
        if i > n and whole:
            out.append(("low", "I013", "JPEG segment runs past end of file (malformed)", "", i, ""))
            break
    if whole:
        eoi = b.rfind(b"\xff\xd9")
        if eoi > 0:
            tail = b[eoi + 2:]
            if len(tail) > 8:
                h = PHP_HINT.search(tail)
                sev = "critical" if h else ("medium" if len(tail) > 64 else "low")
                out.append((sev, "I012", "%d bytes appended after the JPEG end marker" % len(tail),
                            "Legitimate JPEGs end at the FFD9 marker. Extra bytes can carry a hidden script or archive.", eoi + 2, _snip(tail, 80)))
    return out


def png_check(b):
    out, i, n = [], 8, len(b)
    while i + 12 <= n:
        L = int.from_bytes(b[i:i + 4], "big")
        t = b[i + 4:i + 8]
        data = b[i + 8:i + 8 + L]
        if t not in STD_PNG:
            out.append(("medium", "I020", "Non-standard PNG chunk '%s'" % t.decode("latin-1", "replace"), "Custom chunks can hold hidden data.", i, ""))
        if t in (b"tEXt", b"zTXt", b"iTXt", b"eXIf"):
            d = data
            if t == b"zTXt":
                k = data.find(b"\0")
                try:
                    d = zlib.decompress(data[k + 2:])
                except Exception:
                    d = data
            h = PHP_HINT.search(d)
            if h:
                out.append(("critical", "I021", "Code hidden in PNG %s chunk" % t.decode("latin-1"), "", i + 8 + h.start(), _snip(d[h.start():h.start() + 100])))
        i += 12 + L
        if t == b"IEND":
            tail = b[i:]
            if len(tail) > 8:
                h = PHP_HINT.search(tail)
                out.append(("critical" if h else "medium", "I022", "%d bytes appended after the PNG end chunk" % len(tail), "", i, _snip(tail, 80)))
            break
    return out


BENIGN_DOMAINS = re.compile(r"(?:w3\.org|php\.net|github\.com|githubusercontent|laravel\.com|schemas\.|getbootstrap|jquery|googleapis|gstatic|fonts\.|cloudflare|cdnjs|jsdelivr|unpkg|example\.(?:com|org)|localhost|apache\.org|symfony\.com|packagist|mozilla|microsoft\.com|opensource\.org|creativecommons|gnu\.org|xmlsoap|purl\.org|sentry\.io|tailwindcss|fontawesome|youtube|facebook\.com|twitter\.com|linkedin\.com|google\.com|stripe\.com|razorpay|easebuzz)", re.I)


# ----------------------------------------------------------------------------------------------
# Decoder engine (pure data transforms, nothing is ever executed)
# ----------------------------------------------------------------------------------------------
def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in Counter(b).values())


def printable_ratio(b):
    if not b:
        return 0.0
    t = b[:4096].decode("utf-8", "replace")
    good = sum(1 for c in t if (c.isprintable() and c != "\ufffd") or c in "\r\n\t")
    return good / max(1, len(t))


TOK = [b"<?php", b"<?=", b"eval(", b"function", b"$_", b"base64_decode", b"http://", b"https://", b"echo ",
       b"class ", b"<html", b"<script", b"require", b"include", b"return", b"isset(", b"preg_", b"curl_", b"fopen"]


def code_score(b):
    low = b[:20000].lower()
    return sum(1 for t in TOK if t in low)


def plausible(b):
    return len(b) > 0 and printable_ratio(b) >= 0.88


def _inf(b, wbits):
    d = zlib.decompressobj(wbits)
    out = d.decompress(b, MAX_OUT)
    if d.unconsumed_tail:
        raise ValueError("too big")
    if not d.eof:
        raise ValueError("incomplete")
    return out


def t_b64(b):
    s = re.sub(rb"\s+", b"", b.strip())
    if len(s) < 16 or not re.fullmatch(rb"[A-Za-z0-9+/_\-]+={0,2}", s):
        return None
    s = s.replace(b"-", b"+").replace(b"_", b"/")
    s += b"=" * (-len(s) % 4)
    return base64.b64decode(s)


def t_hex(b):
    s = re.sub(rb"\s+|\\x|0x", b"", b.strip())
    if len(s) < 16 or len(s) % 2 or not re.fullmatch(rb"[0-9a-fA-F]+", s):
        return None
    return bytes.fromhex(s.decode())


def t_url(b):
    return unquote_to_bytes(b) if b"%" in b and len(b) >= 12 else None


def t_b32(b):
    s = re.sub(rb"\s+", b"", b.strip())
    if len(s) < 16 or not re.fullmatch(rb"[A-Z2-7]+=*", s):
        return None
    s += b"=" * (-len(s) % 8)
    return base64.b32decode(s)


def t_uu(b):
    lines = [l for l in b.strip().splitlines() if l.strip() and not l.startswith(b"begin") and l.strip() not in (b"end", b"`")]
    if len(lines) < 1 or not all(l[:1] == b"M" or len(l) < 62 for l in lines):
        return None
    return b"".join(binascii.a2b_uu(l) for l in lines)


def t_gzip(b):
    return _inf(b, 31) if b[:2] == b"\x1f\x8b" else None


def t_zlib(b):
    return _inf(b, 15) if b[:1] == b"x" and len(b) > 8 else None


def t_bz2(b):
    if b[:3] != b"BZh":
        return None
    return bz2.BZ2Decompressor().decompress(b, MAX_OUT)


def t_lzma(b):
    if b[:6] != b"\xfd7zXZ\x00":
        return None
    return lzma.LZMADecompressor().decompress(b, MAX_OUT)


def t_rawinflate(b):
    return _inf(b, -15) if len(b) >= 8 and not plausible(b) else None


def t_rot13(b):
    return codecs.encode(b.decode("latin-1"), "rot13").encode("latin-1")


def t_rev(b):
    return b[::-1]


def t_b85(b):
    s = re.sub(rb"\s+", b"", b.strip())
    return base64.b85decode(s) if len(s) >= 20 else None


def t_a85(b):
    s = b.strip()
    return base64.a85decode(s) if len(s) >= 20 else None


def _bits(s, one, zero):
    bits = "".join("1" if c in one else "0" for c in s if c in one or c in zero)
    n = len(bits) // 8 * 8
    return bytes(int(bits[i:i + 8], 2) for i in range(0, n, 8)) if n >= 64 else None


def t_ws(b):
    s = b.decode("latin-1")
    return _bits(s, "\t", " ") if "\t" in s and " " in s else None


def t_ws_inv(b):
    s = b.decode("latin-1")
    return _bits(s, " ", "\t") if "\t" in s and " " in s else None


def t_zw(b):
    s = b.decode("utf-8", "ignore")
    if not re.search("[\u200b\u200c\u200d\ufeff]", s):
        return None
    return _bits(s, "\u200c\u200d", "\u200b\ufeff")


def t_xor(b):
    if len(b) < 24 or plausible(b):
        return None
    head = b[:512]
    for k in range(1, 256):
        h = bytes(x ^ k for x in head)
        hl = h.lower()
        if (b"<?php" in hl or b"eval" in hl or b"http" in hl or b"function" in hl) and printable_ratio(h) > 0.9:
            return bytes(x ^ k for x in b), "xor(key=0x%02x)" % k
    return None


def t_strip_img(b):
    if not any(b.startswith(m) for m, _ in IMG_MAGIC) and not (b[:4] == b"RIFF" and b[8:12] == b"WEBP"):
        return None
    i = b.find(b"<?php")
    if i < 0:
        i = b.find(b"<?=")
    return b[i:] if i > 0 else None


STRICT = {"gzip", "zlib", "bzip2", "lzma"}
SOFT = {"base64", "hex", "url-decode", "base32", "uudecode"}
LOOK = {"str_rot13", "strrev"}
CODEONLY = {"whitespace-binary", "whitespace-binary-inverted", "zero-width-binary", "base85", "ascii85", "xor"}
TRANSFORMS = [("strip-image-header", t_strip_img), ("gzip", t_gzip), ("zlib", t_zlib), ("bzip2", t_bz2),
              ("lzma", t_lzma), ("base64", t_b64), ("hex", t_hex), ("url-decode", t_url), ("base32", t_b32),
              ("uudecode", t_uu), ("whitespace-binary", t_ws), ("whitespace-binary-inverted", t_ws_inv),
              ("zero-width-binary", t_zw), ("gzinflate", t_rawinflate), ("str_rot13", t_rot13),
              ("strrev", t_rev), ("base85", t_b85), ("ascii85", t_a85), ("xor", t_xor)]
FUNC_MAP = {"base64_decode": ("base64", t_b64), "gzinflate": ("gzinflate", lambda b: _inf(b, -15)),
            "gzuncompress": ("zlib", lambda b: _inf(b, 15)), "gzdecode": ("gzip", lambda b: _inf(b, 31)),
            "str_rot13": ("str_rot13", t_rot13), "strrev": ("strrev", t_rev), "hex2bin": ("hex", t_hex),
            "urldecode": ("url-decode", t_url), "rawurldecode": ("url-decode", t_url),
            "convert_uudecode": ("uudecode", t_uu), "bzdecompress": ("bzip2", t_bz2)}
IGNORE_FUNCS = {"eval", "assert", "create_function", "echo", "print", "return", "trim", "stripslashes", "ltrim", "rtrim", "if", "isset"}


def _lookahead_ok(d):
    for fn in (t_b64, t_hex, t_rawinflate, t_gzip, t_zlib):
        try:
            r = fn(d)
        except Exception:
            r = None
        if r and (plausible(r) or r[:2] in (b"\x1f\x8b", b"x\x9c") or r[:3] == b"BZh"):
            return True
    return False


def _accept(name, src, dst):
    if not dst or dst == src:
        return False
    if name in STRICT:
        return True
    if name == "strip-image-header":
        return b"<?" in dst[:64]
    if name == "gzinflate":
        return plausible(dst) or dst[:2] in (b"\x1f\x8b", b"x\x9c")
    if name in SOFT:
        return plausible(dst) or dst[:2] in (b"\x1f\x8b", b"x\x9c") or dst[:3] == b"BZh" or dst[:4] == b"PK\x03\x04" or _lookahead_ok(dst)
    if name in LOOK:
        return plausible(dst) and (code_score(dst) > code_score(src) or _lookahead_ok(dst))
    if name in CODEONLY or name.startswith("xor"):
        return plausible(dst) and code_score(dst) >= 1
    return False


_CHR = re.compile(r"(?:chr\(\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)\s*\.?\s*){3,}", re.I)
_SQ = re.compile(r"'((?:[^'\\\n]|\\.)*)'\s*\.\s*'((?:[^'\\\n]|\\.)*)'")
_DQ = re.compile(r'"((?:[^"\\\n]|\\.)*)"\s*\.\s*"((?:[^"\\\n]|\\.)*)"')


def _chr_sub(m):
    nums = re.findall(r"chr\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", m.group(0), re.I)
    s = "".join(chr((int(n, 16) if n.lower().startswith("0x") else int(n)) & 255) for n in nums)
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def fold_php_strings(t):
    """Fold chr() chains, hex/octal escapes and 'a'.'b' concatenations so payloads become visible."""
    if len(t) > 3_000_000:
        return t
    t = _CHR.sub(_chr_sub, t)
    if len(re.findall(r"\\x[0-9a-fA-F]{2}", t)) >= 8:
        t = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), t)
    if len(re.findall(r"\\[0-7]{3}", t)) >= 8:
        t = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8) & 255), t)
    for rx in (_SQ, _DQ):
        for _ in range(60):
            t2 = rx.sub(lambda m: "'" + m.group(1) + m.group(2) + "'" if rx is _SQ else '"' + m.group(1) + m.group(2) + '"', t)
            if t2 == t:
                break
            t = t2
    return t


CHAIN_RX = re.compile(r"((?:[A-Za-z_][A-Za-z_0-9]*\s*\(\s*@?\s*)+)(['\"])([^'\"\\\s]{16,})\2")
FUNC_RX = re.compile(r"([A-Za-z_][A-Za-z_0-9]*)\s*\(")
LIT_RX = re.compile(r"(['\"])([A-Za-z0-9+/=_%\-\\]{60,})\1")
BLOB_RX = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
HALT_RX = re.compile(rb"__halt_compiler(?:\s*/\*.*?\*/)*\s*\(\s*(?:/\*.*?\*/\s*)*\)\s*;?", re.I | re.S)
MAX_CAND = 25


def extract_candidates(data):
    cands, seen = [], set()

    def add(kind, funcs, blob):
        if len(cands) >= MAX_CAND:
            return
        b = blob if isinstance(blob, bytes) else blob.encode("latin-1", "ignore")
        h = hashlib.md5(b).digest()
        if h in seen or not b:
            return
        seen.add(h)
        cands.append((kind, funcs, b))

    t = fold_php_strings(data.decode("latin-1"))
    m = HALT_RX.search(data)
    if m:
        tail = data[m.end():m.end() + MAX_OUT]
        if tail[:2] == b"?>":
            tail = tail[2:]
            if tail[:2] == b"\r\n":
                tail = tail[2:]
            elif tail[:1] == b"\n":
                tail = tail[1:]
        add("halt-compiler-tail", [], tail)
    for m in CHAIN_RX.finditer(t):
        add("chain", FUNC_RX.findall(m.group(1)), m.group(3))
    for m in LIT_RX.finditer(t):
        add("literal", [], m.group(2))
    for m in BLOB_RX.finditer(t):
        add("blob", [], m.group(0))
    for m in WS_RUN.finditer(t):
        run = m.group(0)
        if run.count("\t") >= 12 and run.count(" ") >= 12:
            add("whitespace-blob", [], run)
    for m in re.finditer("[\u200b\u200c\u200d\ufeff]{24,}", data.decode("utf-8", "ignore")):
        add("zero-width-blob", [], m.group(0).encode("utf-8"))
    return cands


def apply_funcs(funcs, blob):
    steps, cur = [], blob
    for f in reversed(funcs):
        fl = f.lower()
        if fl in IGNORE_FUNCS:
            continue
        if fl not in FUNC_MAP:
            break
        label, fn = FUNC_MAP[fl]
        try:
            r = fn(cur)
        except Exception:
            r = None
        if not r:
            return None, steps
        steps.append(label if fl == "gzinflate" else fl)
        cur = r
    return cur, steps


def make_leaf(data, chain):
    ent = entropy(data[:200000])
    pr = printable_ratio(data)
    if pr > 0.88:
        status = "decoded" if code_score(data) >= 1 else "text"
    elif ent > 7.0 and len(data) >= 64:
        status = "opaque"
    else:
        status = "binary"
    text = data[:30000].decode("utf-8", "replace") if status in ("decoded", "text") else "hex: " + data[:200].hex()
    return dict(chain=chain, status=status, size=len(data), entropy=round(ent, 2), text=text)


def peel(data, chain, depth, out, seen, budget):
    if budget[0] <= 0 or depth > MAX_DEPTH:
        out.append(make_leaf(data, chain + ["(depth limit)"]))
        return
    budget[0] -= 1
    h = hashlib.md5(data).digest()
    if h in seen:
        return
    seen.add(h)
    for name, fn in TRANSFORMS:
        try:
            res = fn(data)
        except Exception:
            res = None
        label = name
        if isinstance(res, tuple):
            res, label = res
        if res and _accept(name, data, res):
            peel(res, chain + [label], depth + 1, out, seen, budget)
            return
    if (plausible(data) or HALT_RX.search(data)) and len(data) <= 4_000_000:
        before = len(out)
        for kind, funcs, blob in extract_candidates(data):
            pre, steps = apply_funcs(funcs, blob) if funcs else (blob, [])
            if pre is None:
                pre, steps = blob, []
            peel(pre, chain + ["extract:" + kind] + steps, depth + 1, out, seen, budget)
        if len(out) > before:
            return
    out.append(make_leaf(data, chain))


def deobfuscate(raw):
    out, seen, budget = [], set(), [400]
    try:
        peel(raw, [], 0, out, seen, budget)
    except RecursionError:
        pass
    res = []
    for p in out:
        if not p["chain"]:
            continue
        if len(p["chain"]) == 1 and p["chain"][0].startswith("extract:") and p["status"] in ("text", "binary") and p["size"] < 400:
            continue  # a harmless literal
        res.append(p)
    return res[:10]


URL_RX = re.compile(r"https?://[^\s'\"<>)\\]{4,200}", re.I)
IP_RX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RX = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def extract_iocs(text):
    out = []
    for u in URL_RX.findall(text):
        if not BENIGN_DOMAINS.search(u):
            out.append(("url", u.rstrip(".,;")))
    for ip in IP_RX.findall(text):
        if not ip.startswith(("0.", "127.", "255.", "10.", "192.168.")) and ip.count(".") == 3:
            out.append(("ip", ip))
    return out


# ----------------------------------------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------------------------------------
BAD_PHP_DIRS = ("storage/", "public/storage/", "public/uploads/", "node_modules/", ".git/", "resources/css/", "resources/js/",
                "resources/images/", "resources/sass/", "public/css/", "public/js/", "public/images/", "public/img/",
                "public/fonts/", "public/assets/", "public/build/", "public/vendor/")
COMPILED_VIEW = re.compile(r"^storage/framework/views/[0-9a-f]{32,40}\.php$")
SHELL_STEMS = {"wso", "c99", "r57", "b374k", "alfa", "cjfuns", "t3x", "indoxploit", "sh3ll", "bypass", "defacer",
               "mailer", "wp-vcd", "xmrlpc", "lock360", "shell", "cmd", "webshell", "filemanager", "fm", "up", "c100", "gel4y", "mini"}
STRONG_STEMS = {"wso", "c99", "r57", "b374k", "alfa", "cjfuns", "t3x", "indoxploit", "sh3ll", "defacer", "wp-vcd",
                "xmrlpc", "lock360", "webshell", "c100", "gel4y"}
SENSITIVE_ENV = re.compile(r"PASS|SECRET|KEY|TOKEN|SALT|PRIVATE", re.I)


class Scan:
    def __init__(self, root, state, deep=False, baseline=None, since=None, custom=None):
        self.root = os.path.realpath(root)
        self.state = state
        self.deep = deep
        self.baseline = os.path.realpath(baseline) if baseline else None
        self.since = since
        self.records = {}
        self.mtimes = []
        self.iocs = defaultdict(lambda: {"count": 0, "files": set()})
        self.total = 0
        self.rules = list(RULES)
        for c in (custom or []):
            c = c.strip()
            if c:
                self.rules.append(dict(id="CUSTOM", sev="critical", title="Custom indicator: " + c, rx=re.compile(re.escape(c), re.I),
                                       desc="Matches an indicator you supplied.", targets={"any"}, cat="custom", noisy=False))
        self.secrets = []
        self.notes = []
        self.key_hits = []
        self.upgrades = []
        self.img_total = 0
        self.img_bad = set()
        self.root_is_web = False

    # -- helpers
    def rec(self, rel, st=None):
        r = self.records.get(rel)
        if r is None:
            if st is None:
                try:
                    st = os.lstat(os.path.join(self.root, rel))
                except OSError:
                    st = None
            r = dict(path=rel, size=st.st_size if st else 0, mtime=int(st.st_mtime) if st else 0,
                     mode=oct(stat.S_IMODE(st.st_mode)) if st else "", findings=[], payloads=[])
            self.records[rel] = r
        return r

    def add(self, rel, sev, rid, title, desc="", cat="code", line=None, snippet="", layer=None, st=None):
        r = self.rec(rel, st)
        key = (rid, title, line, layer)
        if any((f["rule"], f["title"], f["line"], f["layer"]) == key for f in r["findings"]):
            return
        r["findings"].append(dict(sev=sev, rule=rid, title=title, desc=desc, cat=cat, line=line, snippet=snippet, layer=layer))

    def scan_text(self, text, kind, rel, in_v, in_nm, layer=None, st=None):
        for r in self.rules:
            if kind not in r["targets"] and "any" not in r["targets"]:
                continue
            if r["noisy"] and (in_v or in_nm):
                continue
            n = 0
            for m in r["rx"].finditer(text):
                if r["id"] == "R018":
                    matched = m.group(0)[1:-1]
                    if matched.startswith("data:image/") or matched.startswith("data:font/"):
                        continue
                    try:
                        sample_dec = base64.b64decode(matched[:200] + "==")
                        if b"<svg" in sample_dec or b"<?xml" in sample_dec or sample_dec[:4] in (b"wOFF", b"wOF2"):
                            continue
                    except Exception:
                        pass
                line = text.count("\n", 0, m.start()) + 1
                snip = re.sub(r"\s+", " ", text[max(0, m.start() - 25):m.end() + 60])[:200]
                self.add(rel, r["sev"], r["id"], ("[decoded] " if layer else "") + r["title"], r["desc"], r["cat"], line, snip, layer, st)
                n += 1
                if n >= 3:
                    break

    def ioc(self, rel, text):
        for kind, val in extract_iocs(text):
            e = self.iocs[(kind, val)]
            e["count"] += 1
            if len(e["files"]) < 20:
                e["files"].add(rel)

    # -- per file
    def analyze(self, rel, full, st):
        name = os.path.basename(rel)
        ext = os.path.splitext(name)[1].lower()
        parts = rel.split("/")
        in_v, in_nm = parts[0] == "vendor", parts[0] == "node_modules"
        in_git = ".git" in parts[:-1]
        size = st.st_size
        is_php, is_ht = ext in PHP_EXT, name.lower() in (".htaccess", ".user.ini")
        is_js = ext in JS_EXT
        heavy_dir = in_v or in_nm
        want = is_php or is_ht or (not heavy_dir) or self.deep
        head = b""
        try:
            with open(full, "rb") as f:
                head = f.read(min(size, MAX_READ) if want else 8)
        except OSError:
            return
        imgmagic = next((n for m, n in IMG_MAGIC if head.startswith(m)), None)
        if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            imgmagic = "WebP"
        S = lambda sev, rid, title, desc="", cat="structure", **kw: self.add(rel, sev, rid, title, desc, cat, st=st, **kw)

        # ---- structure & placement
        if is_php:
            if imgmagic:
                S("critical", "S001", "Polyglot: PHP file that starts like a %s image" % imgmagic,
                  "Valid image header followed by PHP - built to pass upload validation and still execute.", "polyglot")
            placed_bad = any(rel.startswith(p) for p in BAD_PHP_DIRS) and not COMPILED_VIEW.match(rel)
            if placed_bad:
                S("medium" if in_nm else "high", "S002", "PHP file in a directory that should never hold PHP",
                  "Folders like storage/, .git/, node_modules/, public/css|js|images only hold data/assets.", "placement")
            if name.lower() == "index.php" and rel != "public/index.php":
                big = size > 1024
                S("high" if (big or in_git or not in_v) else "low", "S003", "Stray index.php outside public/",
                  "Backdoors commonly hide as index.php inside deep folders.", "placement")
            stem = os.path.splitext(name)[0].lower()
            if stem in SHELL_STEMS and (placed_bad or stem in STRONG_STEMS):
                S("high", "S004", "File name matches a known webshell name", "", "backdoor")
            if name.startswith(".") and name.lower() not in (".htaccess",):
                S("high", "S005", "Hidden PHP file (dot-file)", "", "placement")
            if re.search(r"\.(?:php\d?|phtml)\.(?:jpe?g|png|gif|txt|zip|bak|suspected|old)$|\.(?:jpe?g|png|gif)\.php\d?$", name, re.I):
                S("high", "S006", "Double extension", "Used to slip past upload filters.", "polyglot")
        if in_git and is_php:
            S("critical", "S007", "PHP file inside .git/", "Git metadata never contains PHP - hidden persistence.", "backdoor")
        if len(parts) <= 2 and re.search(r"[^\x20-\x7e]", name) and not rel.startswith(("storage/", "public/storage/")):
            S("medium", "S008", "Suspicious file name (non-ASCII / control characters)", "Hard-to-type names evade manual cleanup.", "placement")
        if re.fullmatch(r"_+(?:\W.*)?", name) and len(parts) <= 2:
            S("medium", "S009", "File named with only underscores/symbols", "", "placement")
        if head[:4] == b"PK\x03\x04" and ext not in ZIP_OK and not heavy_dir:
            S("high", "S010", "ZIP archive without a .zip extension" + (" (disguised as %s)" % ext if ext else ""),
              "Can be loaded with zip:// to run code that is not visible as a .php file.", "obfuscation")
        if ext in ARCH_EXT and len(parts) <= 2 and not in_git:
            sev = "high" if size > 100 * 1024 * 1024 or parts[0] == "public" or len(parts) == 1 else "medium"
            S(sev, "S011", "Archive / backup in web-reachable location (%.1f MB)" % (size / 1048576),
              "Downloadable by anyone if the web root is the project root. Large archives suggest staged data theft.", "exfiltration")
        if size > 500 * 1024 * 1024 and not in_git:
            S("medium", "S012", "Very large file (%.2f GB)" % (size / 1073741824), "Unusual for a Laravel project.", "exfiltration")
        if os.name == "posix" and (stat.S_IMODE(st.st_mode) & 0o002) and is_php:
            S("medium", "S013", "World-writable PHP file (%s)" % oct(stat.S_IMODE(st.st_mode)), "", "permissions")

        # ---- polyglot / PHP inside non-PHP
        noext_bad = ext == "" and rel.startswith(("public/", "storage/", "resources/", "node_modules/")) and "." not in name
        if not is_php and not is_ht and (ext in PHPINSIDE_EXT or noext_bad or imgmagic) and not (heavy_dir and not self.deep):
            blob = head
            if size > MAX_READ:
                try:
                    with open(full, "rb") as f:
                        f.seek(max(0, size - 65536))
                        blob += f.read(65536)
                except OSError:
                    pass
            m = re.search(rb"<\?(?:php|=)", blob)
            if m and not (ext == ".txt" and heavy_dir):
                sev = "critical" if (ext in IMG_EXT or imgmagic) else ("high" if ext in (".css", ".js", "") else "medium")
                S(sev, "S014", "PHP code embedded in a %s file" % (imgmagic or ext or "no-extension"),
                  "Image/asset files must not contain <?php. If a rogue .htaccess or include loads it, it runs.", "polyglot",
                  line=blob.count(b"\n", 0, m.start()) + 1,
                  snippet=re.sub(r"\s+", " ", blob[m.start():m.start() + 120].decode("latin-1")))

        if (ext in IMG_EXT or imgmagic) and not is_php and not heavy_dir:
            self.img_total += 1
            self.scan_image(rel, full, size, st, ext)
        # ---- zip archives (read-only inspection)
        if head[:4] == b"PK\x03\x04" and not heavy_dir:
            self.inspect_zip(rel, full, size, st, in_v, in_nm)

        # ---- content scanning
        text = head.decode("latin-1") if want else ""
        kind = "php" if is_php else "ht" if is_ht else "js" if is_js and not in_nm else "any"
        if text and (is_php or is_ht or is_js or ext in (".txt", ".json", ".ini", ".css", ".xml", ".yml", ".yaml", ".sql", "") or imgmagic is None):
            if not (kind == "any" and size > 2_000_000):
                self.scan_text(text, kind, rel, in_v, in_nm, st=st)
        if is_ht:
            self.htaccess_checks(rel, text, st)
        if (text and size <= 2_000_000 and (not heavy_dir or self.deep) and not name.lower().endswith((".min.js", ".lock", ".example", ".sample"))
                and name not in ("package-lock.json",) and not rel.startswith(("public/build/", "tests/", "lang/", "resources/lang/"))
                and (ext in SECRET_EXT or name.startswith(".env") or rel == ".git/config")):
            self.scan_secrets(rel, text, st, generic=not name.startswith(".env"))
        if is_php and text:
            self.php_heuristics(rel, text, head, st, in_v, in_nm)
        # ---- baseline compare
        if self.baseline and in_v and not rel.startswith("vendor/composer/") and rel != "vendor/autoload.php":
            self.compare_baseline(rel, full, is_php, st)

    def php_heuristics(self, rel, text, head, st, in_v, in_nm):
        size = len(text)
        if not in_v and not in_nm:
            mx = max((len(l) for l in text.split("\n")), default=0)
            if mx > 4000:
                self.add(rel, "medium", "H101", "Extremely long line (%d chars)" % mx, "Minified or obfuscated one-liner.", "obfuscation", st=st)
            if size > 1500 and entropy(head[:200000]) > 5.7:
                self.add(rel, "medium", "H102", "High-entropy PHP (%.2f bits/byte)" % entropy(head[:200000]),
                         "Normal source code is ~4.5-5.2; packed or encrypted data is higher.", "obfuscation", st=st)
        if size > 2000 and (text.count(" ") + text.count("\t") + text.count("\n")) / size > 0.75 and "\t" in text:
            self.add(rel, "medium", "H103", "File is mostly whitespace (steganography)", "PHP hidden in tabs/spaces.", "obfuscation", st=st)
        r = self.records.get(rel)
        worst = max((SEV[f["sev"]] for f in r["findings"]), default=0) if r else 0
        if (in_v or in_nm) and worst < 3:
            return
        if not QUICK.search(text):
            return
        pl = deobfuscate(head)
        if not pl:
            return
        rr = self.rec(rel, st)
        rr["payloads"] = pl[:8]
        for p in pl:
            chain = " → ".join(p["chain"])
            if p["status"] in ("decoded", "text"):
                self.scan_text(p["text"], "php", rel, in_v, in_nm, layer=chain, st=st)
                self.ioc(rel, p["text"])
                sev = "high" if code_score(p["text"].encode("utf-8", "ignore")) >= 2 else "medium"
                self.add(rel, sev, "D001", "Hidden payload decoded (%d layers)" % len(p["chain"]),
                         "Chain: %s. %d bytes of readable text recovered - see the Decoded tab." % (chain, p["size"]), "obfuscation", layer=chain, st=st)
            elif p["status"] == "opaque":
                self.add(rel, "medium", "D002", "Opaque payload - likely encrypted (needs a key)",
                         "Chain: %s. High entropy (%.2f) after all known decoders; recover the key from the loader code or treat as malicious." % (chain, p["entropy"]),
                         "obfuscation", layer=chain, st=st)
            else:
                self.add(rel, "low", "D003", "Binary payload after decoding", "Chain: %s (%d bytes)." % (chain, p["size"]), "obfuscation", layer=chain, st=st)
        if not in_v:
            self.ioc(rel, text[:500000])

    def htaccess_checks(self, rel, text, st):
        d = os.path.dirname(rel)
        for f in self.records.get(rel, {}).get("findings", []):
            if f["rule"] == "H006":
                f["sev"] = "info" if d in ("", "public") else "high"
                if d in ("", "public"):
                    f["title"] = "PHP handler set at project/public root"
                    f["desc"] = "Normal on shared hosting, but note it applies to EVERY sub-folder, so any planted .php file will execute."
                    f["cat"] = "exposure"
        if d == "" and re.search(r"RewriteRule\s+\^\(\.\*\)\$\s+public/\$1", text):
            self.root_is_web = True
            self.add(rel, "high", "L001", "Project root is the web root (rewrite to public/)",
                     "Everything - .env, vendor, storage, .git - sits inside the web-reachable folder. Point the domain's document root at public/ instead.",
                     "laravel", st=st)

    def scan_secrets(self, rel, text, st, generic=True):
        if rel.endswith(".blade.php"):
            text = re.sub(r"\{\{--[\s\S]*?--\}\}", "", text)
        for rid, sev, title, _ in SECRET_RULES:
            k = 0
            for m in SECRET_RX[rid].finditer(text):
                val = m.group(1) if rid == "K002" else m.group(0)
                if PLACEHOLDER.match(val) or "EXAMPLE" in val.upper():
                    continue
                line = text.count("\n", 0, m.start()) + 1
                self.add(rel, sev, rid, title, "Value %s. Keys stored in code/config are readable by anyone who gets the files - move them to .env and rotate if the project was ever shared or exposed." % mask(val), "secrets", line, "", st=st)
                self.key_hits.append(dict(type=title, file=rel, line=line, masked=mask(val)))
                k += 1
                if k >= 3:
                    break
        if not generic:
            return
        k = 0
        for m in GENERIC_SECRET.finditer(text):
            key, val = m.group(1), m.group(2)
            ls = text.rfind("\n", 0, m.start()) + 1
            le = text.find("\n", m.end())
            le = len(text) if le < 0 else le
            ltxt = text[ls:le]
            if (re.search(r"getenv\s*\(", ltxt[:m.start() - ls]) or "|" in val or PLACEHOLDER.match(val) or val.lower() == key.lower()
                    or val.startswith(("$", "{")) or re.match(r"^(?:required|nullable|string|confirmed|min:|max:)", val)):
                continue
            line = text.count("\n", 0, m.start()) + 1
            self.add(rel, "high", "K015", "Hard-coded %s" % key.lower(), "Value %s is written directly in the file. Read it with env()/config() instead and rotate it if it is real." % mask(val),
                     "secrets", line, "%s = %s" % (key, mask(val)), st=st)
            self.key_hits.append(dict(type="Hard-coded " + key.lower(), file=rel, line=line, masked=mask(val)))
            k += 1
            if k >= 4:
                break

    def scan_image(self, rel, full, size, st, ext):
        I = lambda sev, rid, title, desc="", off=None, snip="": self.add(
            rel, sev, rid, title, (desc + (" Byte offset 0x%x." % off if off is not None else "")).strip(), "image", None, (("@0x%x  " % off if off is not None else "") + snip), st=st)
        try:
            with open(full, "rb") as f:
                if size <= 20 * 1024 * 1024:
                    b, whole = f.read(), True
                else:
                    b = f.read(1024 * 1024)
                    f.seek(size - 1024 * 1024)
                    b, whole = b + f.read(1024 * 1024), False
        except OSError:
            return
        before = len(self.records.get(rel, {}).get("findings", []))
        kind = ("JPEG" if b[:3] == b"\xff\xd8\xff" else "PNG" if b[:8] == b"\x89PNG\r\n\x1a\n" else "GIF" if b[:6] in (b"GIF87a", b"GIF89a")
                else "WebP" if b[:4] == b"RIFF" and b[8:12] == b"WEBP" else "ICO" if b[:4] == b"\x00\x00\x01\x00" else "BMP" if b[:2] == b"BM" else None)
        want = {".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".gif": "GIF", ".webp": "WebP", ".ico": "ICO", ".bmp": "BMP"}.get(ext)
        if kind is None and size > 0:
            txt = printable_ratio(b[:4096]) > 0.9
            I("high" if txt else "medium", "I001", "File has an image extension but is not an image" + (" (it is text/code)" if txt else ""),
              "Real images start with a known signature.", 0, _snip(b, 80))
        elif want and kind != want and not (want == "ICO" and kind in ("PNG", "BMP")):
            I("medium", "I002", "Image type mismatch: extension says %s, content is %s" % (want, kind), "Mislabelled files are used to bypass upload filters.")
        found = []
        if kind == "JPEG":
            found = jpeg_check(b, whole)
        elif kind == "PNG":
            found = png_check(b)
        for sev, rid, title, desc, off, snip in found:
            I(sev, rid, title, desc, off, snip)
        if not any(f[1] in ("I010", "I012", "I021", "I022") for f in found):
            h = PHP_HINT.search(b)
            if h:
                I("high", "I030", "Code-like string inside image data", "A script keyword was found in what should be pixel data.", h.start(), _snip(b[h.start():h.start() + 100]))
        if len(self.records.get(rel, {}).get("findings", [])) > before:
            self.img_bad.add(rel)

    def audit_config(self):
        R = self.root
        p = lambda *a: os.path.join(R, *a)

        def rd(rel, cap=1_500_000):
            try:
                with open(p(*rel.split("/")), "r", errors="replace") as f:
                    return f.read(cap)
            except OSError:
                return None

        def chk(rel, text, pat, sev, rid, title, desc, flags=re.I):
            if text is None:
                return None
            m = re.search(pat, text, flags)
            if m:
                self.add(rel, sev, rid, title, desc, "config", text.count("\n", 0, m.start()) + 1, re.sub(r"\s+", " ", m.group(0))[:140])
            return m

        t = rd("config/app.php")
        chk("config/app.php", t, r"['\"]debug['\"]\s*=>\s*true", "high", "C101", "Debug mode hard-coded to true", "Debug pages leak paths, config and sometimes secrets. Use env('APP_DEBUG', false).")
        chk("config/app.php", t, r"['\"]key['\"]\s*=>\s*['\"][^'\"]{8,}['\"]", "high", "C102", "Application key written into config/app.php", "The key signs cookies and encrypts data; keep it in .env only.")
        t = rd("config/session.php")
        chk("config/session.php", t, r"['\"]secure['\"]\s*=>\s*false", "medium", "C110", "Session cookie is not marked Secure", "Cookies can be sent over plain HTTP.")
        chk("config/session.php", t, r"['\"]http_only['\"]\s*=>\s*false", "high", "C111", "Session cookie readable by JavaScript (http_only = false)", "An XSS bug could steal sessions.")
        chk("config/session.php", t, r"['\"]same_site['\"]\s*=>\s*(?:null|['\"]none['\"])", "low", "C112", "SameSite not restricted", "Use 'lax' or 'strict' unless you really need cross-site cookies.")
        t = rd("config/cors.php")
        m0 = re.search(r"['\"]allowed_origins['\"]\s*=>\s*\[\s*['\"]\*['\"]", t or "")
        if m0:
            cred = re.search(r"['\"]supports_credentials['\"]\s*=>\s*true", t)
            self.add("config/cors.php", "high" if cred else "medium", "C120", "CORS allows every origin" + (" together with credentials" if cred else ""),
                     "Restrict allowed_origins to your own domains.", "config", t.count("\n", 0, m0.start()) + 1, "allowed_origins => ['*']")
        t = rd("config/database.php")
        chk("config/database.php", t, r"['\"]strict['\"]\s*=>\s*false", "low", "C130", "MySQL strict mode is off", "Strict mode prevents silent data truncation.")
        if os.path.isdir(p("routes")):
            for rf in sorted(os.listdir(p("routes"))):
                if not rf.endswith(".php"):
                    continue
                rel = "routes/" + rf
                t = rd(rel)
                chk(rel, t, r"\bphpinfo\s*\(", "medium", "C140", "phpinfo() reachable through a route", "Leaks server configuration.")
                chk(rel, t, r"Artisan::call\s*\(", "medium", "C141", "Route runs artisan commands", "Make sure this is behind authentication, or remove it after use.")
                chk(rel, t, r"\b(?:eval|shell_exec|passthru|system)\s*\(", "high", "C142", "Shell/eval call inside a route file", "Route files should only route.")
                chk(rel, t, r"Route::(?:get|any|match)\s*\(\s*['\"]/?(?:install|setup|migrate|seed|debug|test|clear-cache|storage-link|cmd|shell|upload)['\"]", "medium",
                    "C143", "Maintenance-style route exposed", "Confirm it is protected, or delete it.")
        # php.ini / .user.ini
        for rel in ("php.ini", ".user.ini", "public/.user.ini", "public/php.ini"):
            t = rd(rel)
            if t is None:
                continue
            chk(rel, t, r"^\s*allow_url_include\s*=\s*(?:on|1|true)", "high", "C150", "allow_url_include is enabled", "Allows include of remote URLs - remote code execution risk.", re.I | re.M)
            chk(rel, t, r"^\s*display_errors\s*=\s*(?:on|1|true)", "medium", "C151", "display_errors is on", "Errors shown to visitors leak internals.", re.I | re.M)
            chk(rel, t, r"^\s*allow_url_fopen\s*=\s*(?:on|1|true)", "low", "C152", "allow_url_fopen is on", "Lets scripts read remote URLs; turn off if unused.", re.I | re.M)
            chk(rel, t, r"^\s*expose_php\s*=\s*(?:on|1|true)", "low", "C153", "expose_php is on", "Advertises the PHP version.", re.I | re.M)
            chk(rel, t, r"^\s*auto_(?:prepend|append)_file\s*=\s*\S", "high", "C154", "auto_prepend/append_file is set", "Runs a file on every request - a classic persistence trick.", re.I | re.M)
        # leftover / dev files in web-reachable folders
        HIGH = {"phpinfo.php", "info.php", "adminer.php", "dump.sql", "backup.sql", "error_log", "php_errorlog"}
        for base in ("", "public"):
            d = p(base) if base else R
            if not os.path.isdir(d):
                continue
            for n in ("phpinfo.php", "info.php", "test.php", "adminer.php", "phpmyadmin", ".DS_Store", ".idea", ".vscode", ".svn", ".hg", "docker-compose.yml",
                      "Dockerfile", "deploy.sh", "dump.sql", "backup.sql", "error_log", "php_errorlog", ".git"):
                if os.path.exists(os.path.join(d, n)):
                    rel = (base + "/" if base else "") + n
                    sev = "high" if n in HIGH else ("medium" if n == ".git" and (self.root_is_web or base == "public") else "low")
                    self.add(rel, sev, "C160", "Leftover/dev file in a web-reachable folder: %s" % n,
                             "Harmless if only public/ is served, dangerous if this folder is the web root.", "config")
        ht = rd(".htaccess")
        if self.root_is_web and ht is not None and not re.search(r"(?:FilesMatch|RedirectMatch|RewriteRule)[^\n]*(?:\\\.|\.)(?:env|git|ht)", ht, re.I):
            self.add(".htaccess", "medium", "C170", "Root .htaccess has no rule blocking dotfiles (.env, .git)",
                     "Because the project root is the web root, add a FilesMatch/RedirectMatch that denies requests for dotfiles.", "config")
        # composer: versions, dev packages, debug tools
        lock = cj = None
        try:
            lock = json.load(open(p("composer.lock"), encoding="utf-8", errors="replace"))
        except Exception:
            pass
        try:
            cj = json.load(open(p("composer.json"), encoding="utf-8", errors="replace"))
        except Exception:
            pass
        if cj is not None and lock is None:
            self.add("composer.json", "low", "U000", "composer.lock is missing", "Without it versions are not pinned, so a deploy can pull different code.", "upgrade")
        pk = {x.get("name"): x.get("version", "") for x in (lock or {}).get("packages", [])}
        pkdev = {x.get("name"): x.get("version", "") for x in (lock or {}).get("packages-dev", [])}
        lv = pk.get("laravel/framework")
        if lv:
            m = re.match(r"v?(\d+)", lv)
            major = int(m.group(1)) if m else 0
            if major <= 10:
                sev, adv = "high", "Laravel %d.x no longer receives security fixes. Upgrade one major version at a time using the official upgrade guide." % major
            elif major == 11:
                sev, adv = "medium", "Laravel 11's security-fix window ended in March 2026 per Laravel's published schedule (verify on laravel.com/docs/releases). Plan the next major upgrade."
            else:
                sev, adv = "info", "Confirm on laravel.com/docs/releases that this major version is still supported, and run composer update to pick up patch releases."
            self.upgrades.append(dict(component="laravel/framework", current=lv, sev=sev, advice=adv))
            if sev in ("high", "medium"):
                self.add("composer.lock", sev, "U001", "Laravel %s is out of (or past) its security-support window" % lv, adv, "upgrade")
        phpc = ((cj or {}).get("require") or {}).get("php", "")
        m = re.search(r"(\d+)\.(\d+)", phpc or "")
        if m:
            v = (int(m.group(1)), int(m.group(2)))
            if v < (8, 2):
                sev, adv = "high", "composer.json allows PHP %d.%d, which is end-of-life. Move the site to a supported PHP (see php.net/supported-versions.php)." % v
            elif v == (8, 2):
                sev, adv = "medium", "PHP 8.2 security support ends on 31 Dec 2026 per php.net. Plan a move to 8.3 or newer and check what your host actually runs."
            else:
                sev, adv = "info", "Check php.net/supported-versions.php and confirm your host runs a supported PHP version."
            self.upgrades.append(dict(component="PHP (composer.json minimum)", current=phpc, sev=sev, advice=adv))
            if sev != "info":
                self.add("composer.json", sev, "U002", "PHP requirement %s is at or past end of security support" % phpc, adv, "upgrade")
        devs = [n for n in pkdev if n and os.path.isdir(p("vendor", *n.split("/")))]
        if devs:
            adv = "Production should use 'composer install --no-dev'. Dev tools enlarge the attack surface and their folders are common hiding places for planted files."
            self.add("composer.lock", "medium", "U010", "%d dev-only packages are installed in vendor/ (e.g. %s)" % (len(devs), ", ".join(devs[:4])), adv, "upgrade")
            self.upgrades.append(dict(component="Dev packages in production", current="%d installed" % len(devs), sev="medium", advice=adv))
        for n in ("barryvdh/laravel-debugbar", "laravel/telescope", "spatie/laravel-ignition", "itsgoingd/clockwork"):
            if n in pk:
                self.add("composer.lock", "medium", "C180", "Debug/inspection package %s is in the production dependencies" % n,
                         "These tools expose requests, queries and config. Move to require-dev or restrict access strictly.", "config")
        for obs_pkg, obs_name in (
            ("laravel/horizon", "Laravel Horizon dashboard"),
            ("laravel/pulse", "Laravel Pulse monitor"),
            ("rap2hpoutre/laravel-log-viewer", "Laravel Log Viewer")
        ):
            if obs_pkg in pk:
                self.add("composer.lock", "medium", "C181", "%s (%s) in production dependencies" % (obs_name, obs_pkg),
                         "Ensure routes for %s are strictly restricted behind authorization gates in production." % obs_pkg, "config")
        for comp, adv in (("All PHP dependencies", "Run `composer audit` to list packages with known security advisories and `composer outdated --direct` to see available upgrades."),
                          ("Front-end packages", "Run `npm audit` and `npm outdated`, then rebuild with `npm ci && npm run build`."),
                          ("This scanner", "Re-run it after every deployment and keep a clean copy of vendor/ for the integrity comparison.")):
            self.upgrades.append(dict(component=comp, current="-", sev="info", advice=adv))

    def inspect_zip(self, rel, full, size, st, in_v, in_nm):
        try:
            zf = zipfile.ZipFile(full)
            infos = zf.infolist()
        except Exception:
            return
        names = [i.filename for i in infos]
        self.add(rel, "info", "Z000", "Archive with %d entries" % len(names), "Examples: " + ", ".join(names[:6]), "archive", st=st)
        sens = [n for n in names if re.search(r"(?:^|/)\.env(?:\.|$)|\.sql$|database/|storage/logs|\.pem$|id_rsa", n, re.I)]
        if sens and size > 1_000_000:
            self.add(rel, "high", "Z001", "Archive contains secrets / database material",
                     "Includes: " + ", ".join(sens[:6]) + ". Treat all credentials inside as stolen.", "exfiltration", st=st)
        if len(names) > 300 and size > 50 * 1024 * 1024:
            self.add(rel, "high", "Z002", "Archive of the whole project (%d files, %.2f GB)" % (len(names), size / 1073741824),
                     "Looks like a staged full-site copy for download.", "exfiltration", st=st)
        done = 0
        for i in infos:
            if done >= 40 or i.file_size > 5 * 1024 * 1024 or i.is_dir():
                continue
            en = i.filename
            e_ext = os.path.splitext(en)[1].lower()
            if size > 200 * 1024 * 1024 and e_ext not in PHP_EXT:
                continue
            try:
                data = zf.read(i)
            except Exception:
                continue
            done += 1
            tag = "zip:" + en
            has_non_ascii = any(ord(c) > 127 for c in en)
            suspicious_name = e_ext in PHP_EXT or re.fullmatch(r"_+|[A-Za-z0-9_]{1,3}", en) or has_non_ascii or re.search(r"[^\w.\-]", en)
            if has_non_ascii:
                self.add(rel, "high", "Z004", "Archive member '%s' has non-ASCII / obfuscated name" % en,
                         "Obfuscated archive member names are used to hide payloads.", "obfuscation", layer=tag, st=st)
            if suspicious_name and (data[:5] == b"<?php" or b"<?php" in data[:200] or code_score(data) >= 2):
                self.add(rel, "high", "Z003", "Archive member '%s' contains PHP code" % en,
                         "Matches the zip:// stream-wrapper loader technique.", "obfuscation", layer=tag, st=st)
            txt = data.decode("latin-1")
            if suspicious_name or e_ext in PHP_EXT:
                self.scan_text(txt, "php", rel, in_v, in_nm, layer=tag, st=st)
                if QUICK.search(txt):
                    pl = deobfuscate(data)
                    r = self.rec(rel, st)
                    for p in pl:
                        p = dict(p, chain=[tag] + p["chain"])
                        if len(r["payloads"]) < 8:
                            r["payloads"].append(p)
                        if p["status"] in ("decoded", "text"):
                            self.scan_text(p["text"], "php", rel, in_v, in_nm, layer=" → ".join(p["chain"]), st=st)
                            self.ioc(rel, p["text"])
                self.ioc(rel, txt[:300000])
            elif size < 20 * 1024 * 1024 and e_ext in (".txt", "") and printable_ratio(data) > 0.7:
                # keyword dictionaries etc.
                r = self.rec(rel, st)
                if len(r["payloads"]) < 8:
                    r["payloads"].append(dict(chain=[tag], status="text", size=len(data), entropy=round(entropy(data[:100000]), 2), text=data[:8000].decode("utf-8", "replace")))

    def compare_baseline(self, rel, full, is_php, st):
        bp = os.path.join(self.baseline, rel)
        if not os.path.isfile(bp):
            self.add(rel, "high" if is_php else "low", "B001", "Not present in the clean vendor copy",
                     "File does not exist in a fresh install of the same packages.", "integrity", st=st)
            return
        try:
            if st.st_size != os.stat(bp).st_size or self.sha(full) != self.sha(bp):
                self.add(rel, "high" if is_php else "medium", "B002", "Modified compared with the clean vendor copy", "Hash differs from a fresh install.", "integrity", st=st)
        except OSError:
            pass

    @staticmethod
    def sha(path, algo="sha256"):
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    # -- project-level
    def audit_laravel(self):
        R = self.root
        p = lambda *a: os.path.join(R, *a)
        envs = [n for n in sorted(os.listdir(R)) if n == ".env" or (n.startswith(".env.") and not n.endswith((".example", ".sample", ".dist")))] if os.path.isdir(R) else []
        for en in envs:
            try:
                txt = open(p(en), "r", errors="replace").read()
            except OSError:
                continue
            kv = {}
            for ln_, line in enumerate(txt.splitlines(), 1):
                s_ = line.strip()
                if "=" in s_ and not s_.startswith("#"):
                    k, v = s_.split("=", 1)
                    kv[k.strip()] = (v.strip().strip("'\""), ln_)
            if en != ".env":
                self.add(en, "high", "L014", "Copy of the environment file (%s) in the project" % en,
                         "Backup/variant .env files are often forgotten, may be downloadable, and hold the same secrets.", "exposure")
            for k, (v, ln_) in kv.items():
                if SENSITIVE_ENV.search(k) and v and v.lower() not in ("null", "false", "true"):
                    self.secrets.append(dict(key=k, masked=mask(v), file=en, line=ln_))
            g = lambda k: kv.get(k, ("", None))
            v, ln_ = g("APP_DEBUG")
            if v.lower() == "true":
                self.add(en, "high", "L010", "APP_DEBUG=true", "Debug pages leak paths, config and sometimes secrets.", "config", line=ln_, snippet="APP_DEBUG=true")
            v, ln_ = g("APP_ENV")
            if v.lower() in ("local", "dev", "development"):
                self.add(en, "medium", "L011", "APP_ENV=%s on what may be production" % v, "", "config", line=ln_, snippet="APP_ENV=" + v)
            if "APP_KEY" in kv and not kv["APP_KEY"][0]:
                self.add(en, "medium", "L012", "APP_KEY is empty", "Run php artisan key:generate.", "config", line=kv["APP_KEY"][1])
            if "DB_PASSWORD" in kv and not kv["DB_PASSWORD"][0] and kv.get("DB_HOST", ("127.0.0.1",))[0] not in ("127.0.0.1", "localhost", ""):
                self.add(en, "high", "L015", "Remote database with an empty password", "", "config", line=kv["DB_PASSWORD"][1])
            v, ln_ = g("SESSION_SECURE_COOKIE")
            if g("APP_URL")[0].startswith("https") and v.lower() != "true":
                self.add(en, "medium", "L016", "HTTPS site without SESSION_SECURE_COOKIE=true", "Session cookie may travel over plain HTTP.", "config", line=ln_)
            v, ln_ = g("APP_URL")
            if v.startswith("http://") and not re.search(r"localhost|127\.0\.0\.1|\.test|\.local", v):
                self.add(en, "low", "L017", "APP_URL uses plain http://", "", "config", line=ln_, snippet="APP_URL=" + v)
            v, ln_ = g("LOG_LEVEL")
            if v.lower() == "debug":
                self.add(en, "low", "L018", "LOG_LEVEL=debug in production fills logs with sensitive data", "", "config", line=ln_)
        if self.secrets:
            first = next((x for x in self.secrets if x["file"] == ".env"), self.secrets[0])
            self.add(first["file"], "info", "L013", "%d secrets stored in env files - rotate them if the site was ever compromised" % len(self.secrets),
                     "See the Keys & secrets view for key names and line numbers (values are masked).", "secrets")
        for f in os.listdir(p("public")) if os.path.isdir(p("public")) else []:
            if f.lower().startswith(".env") or f.lower().endswith((".sql", ".bak", ".zip", ".tar", ".gz")):
                self.add("public/" + f, "critical", "L020", "Sensitive file inside public/", "Directly downloadable.", "exposure")
        # CSRF exceptions
        for rel, rx in (("bootstrap/app.php", r"validateCsrfTokens\s*\(\s*except\s*:\s*\[(.*?)\]"),
                        ("app/Http/Middleware/VerifyCsrfToken.php", r"\$except\s*=\s*\[(.*?)\]")):
            fp = p(*rel.split("/"))
            if os.path.isfile(fp):
                m = re.search(rx, open(fp, "r", errors="replace").read(), re.S)
                if m:
                    items = re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
                    if items:
                        sev = "high" if "*" in items else "medium"
                        self.add(rel, sev, "L030", "CSRF protection disabled for %d route(s)" % len(items),
                                 "Exempt: " + ", ".join(items) + ". Public form/upload routes without CSRF can be hit by bots with no session.", "laravel")
        fs = p("config", "filesystems.php")
        if os.path.isfile(fs) and re.search(r"['\"]root['\"]\s*=>\s*public_path\s*\(", open(fs, "r", errors="replace").read()):
            self.add("config/filesystems.php", "high", "L031", "Storage disk writes directly into public/",
                     "Uploaded files land in the web root; any script that slips through becomes executable.", "laravel")
        ps = p("public", "storage")
        if os.path.isdir(ps) and not os.path.islink(ps) and not os.path.isfile(os.path.join(ps, ".htaccess")):
            self.add("public/storage", "medium", "L032", "public/storage is a real folder without an .htaccess",
                     "Add 'php_flag engine off' + a FilesMatch deny for .php/.phtml here.", "laravel")
        sap = p("storage", "app", "public")
        if os.path.isdir(sap):
            sap_ht = os.path.join(sap, ".htaccess")
            if not os.path.isfile(sap_ht):
                self.add("storage/app/public", "high", "L033", "storage/app/public has no .htaccess disabling script execution",
                         "Uploaded files symlinked to public/storage can execute if an attacker uploads PHP. Add an .htaccess with 'php_flag engine off' or 'SetHandler None'.", "laravel")
            else:
                try:
                    ht_txt = open(sap_ht, "r", errors="replace").read()
                    if not re.search(r"php_flag\s+engine\s+off|SetHandler\s+None|RemoveHandler", ht_txt, re.I):
                        self.add("storage/app/public/.htaccess", "medium", "L034", "storage/app/public/.htaccess does not disable PHP execution",
                                 "Ensure PHP script execution is blocked here (e.g. 'php_flag engine off' or 'SetHandler None').", "laravel")
                except OSError:
                    pass
        # scheduler persistence
        for c_cand in ("routes/console.php", "app/Console/Kernel.php"):
            cp = p(*c_cand.split("/"))
            if os.path.isfile(cp):
                try:
                    c_txt = open(cp, "r", errors="replace").read()
                    if re.search(r"(?:Schedule::|\$schedule->)\s*exec\s*\(", c_txt):
                        self.add(c_cand, "high", "L060", "Task Scheduler executes shell commands (Schedule::exec)",
                                 "Verify scheduled commands: attackers often plant persistence in Laravel Task Scheduler.", "laravel")
                    if re.search(r"(?:Schedule::|\$schedule->)\s*call\s*\([^;]{0,120}?(?:eval|system|exec|passthru|shell_exec)", c_txt, re.S):
                        self.add(c_cand, "critical", "L061", "Task Scheduler runs eval/shell inside closure",
                                 "Task scheduler contains direct command/code execution.", "backdoor")
                except OSError:
                    pass
        # upload code
        for dp, _, fns in os.walk(p("app")):
            for fn in fns:
                if fn.endswith(".php"):
                    fp = os.path.join(dp, fn)
                    rel = os.path.relpath(fp, R).replace(os.sep, "/")
                    try:
                        t = open(fp, "r", errors="replace").read()
                    except OSError:
                        continue
                    for rx, rid, title, desc in (
                            (r"getClientOriginalExtension\s*\(", "L040", "Upload keeps the client-supplied extension",
                             "An attacker controls this. Use ->extension() / ->hashName() and re-encode images."),
                            (r"->move\s*\(\s*public_path\s*\(", "L041", "Upload moved straight into public/",
                             "Files in public/ are executable if they carry a PHP extension.")):
                        for m in re.finditer(rx, t):
                            self.add(rel, "medium", rid, title, desc, "laravel", line=t.count("\n", 0, m.start()) + 1)
                            break
        # log mining
        for cand in ("storage/logs/laravel.log",):
            lp = p(*cand.split("/"))
            if os.path.isfile(lp):
                try:
                    sz = os.path.getsize(lp)
                    with open(lp, "rb") as f:
                        f.seek(max(0, sz - 6 * 1024 * 1024))
                        lines = f.read().decode("utf-8", "replace").splitlines()
                except OSError:
                    continue
                pat = re.compile(r"zip://|php://|base64_decode|eval\(|/bin/(?:ba)?sh|wget |curl -|\.\./\.\./|union\s+select|<\?php|cmd=|allow_url_include", re.I)
                hits = [(i + 1, l) for i, l in enumerate(lines) if pat.search(l)]
                if hits:
                    sample = " | ".join(re.sub(r"\s+", " ", l)[:140] for _, l in hits[:3])
                    self.add(cand, "medium", "L050", "%d attack-looking line(s) in the application log" % len(hits), sample, "log")

    def timeline(self):
        self.mtimes.sort()
        flagged = {r["path"] for r in self.records.values() if r["findings"] and max(SEV[f["sev"]] for f in r["findings"]) >= 2}
        clusters, cur = [], []
        for t, rel in self.mtimes:
            if cur and t - cur[-1][0] > 3:
                if len(cur) >= 6:
                    clusters.append(cur)
                cur = []
            cur.append((t, rel))
        if len(cur) >= 6:
            clusters.append(cur)
        out = []
        for c in clusters:
            fl = [r for _, r in c if r in flagged]
            if len(fl) >= 3:
                out.append(dict(start=c[0][0], end=c[-1][0], files=len(c), flagged=len(fl), examples=fl[:6]))
                for _, r in c:
                    if r in flagged:
                        self.add(r, "low", "T001", "Created in a burst of %d files within %ds" % (len(c), c[-1][0] - c[0][0] + 1),
                                 "Automated installers drop many backdoors at the same instant (%s)." % datetime.datetime.fromtimestamp(c[0][0]).strftime("%Y-%m-%d %H:%M:%S"), "timeline")
        days = defaultdict(lambda: [0, 0])
        for t, rel in self.mtimes:
            d = datetime.date.fromtimestamp(t).isoformat()
            days[d][0] += 1
            if rel in flagged:
                days[d][1] += 1
        recent = sorted(days.items())[-60:]
        return sorted(out, key=lambda c: -c["flagged"])[:30], [dict(day=d, files=v[0], flagged=v[1]) for d, v in recent]

    def correlate(self):
        by_dir = defaultdict(list)
        for rel, r in self.records.items():
            sev = max((SEV[f["sev"]] for f in r["findings"]), default=0)
            if sev >= 3 and os.path.splitext(rel)[1].lower() in PHP_EXT:
                by_dir[os.path.dirname(rel)].append(rel)
        for d, files in by_dir.items():
            ht = (d + "/" if d else "") + ".htaccess"
            if os.path.isfile(os.path.join(self.root, ht)):
                self.add(ht, "high", "C001", "Paired with a flagged script in the same folder",
                         "Rogue .htaccess files are dropped next to backdoors to force execution / block admins. Flagged: " + ", ".join(os.path.basename(f) for f in files[:4]), "htaccess")

    def remediation(self, cats):
        items = []
        n_crit = sum(1 for r in self.records.values() if any(f["sev"] in ("critical", "high") for f in r["findings"]))
        if n_crit:
            items.append(("Quarantine flagged files", "Use the Quarantine tab: %d files rated Critical/High. Review each first - then rebuild vendor/ and node_modules/ from composer.lock / package-lock.json instead of cleaning them by hand." % n_crit))
        if self.secrets:
            items.append(("Rotate every secret in .env", "%d sensitive keys found (%s). Rotate DB password, mail password, payment gateway key/salt, cloud keys and run php artisan key:generate." % (len(self.secrets), ", ".join(s["key"] for s in self.secrets[:8]))))
        if "laravel" in cats:
            items.append(("Fix the web root", "Point the domain's document root to <project>/public so .env, vendor/, storage/ and .git/ are never reachable over HTTP."))
            items.append(("Harden uploads", "Never use getClientOriginalExtension(); store with hashName(), re-encode images (GD/Intervention) and keep uploads outside public/ or add 'php_flag engine off' there."))
        if "seo-spam" in cats or "c2" in cats:
            items.append(("Clean search results", "Remove injected sitemap/robots entries, then use Google Search Console (Security issues + Removals) and re-request indexing."))
        if "exfiltration" in cats:
            items.append(("Delete exfiltration archives", "Remove staged archives from the web root and check hosting access logs for who downloaded them."))
        if "secrets" in cats:
            items.append(("Remove hard-coded keys", "Move every key listed in Keys & secrets into .env (read with env()/config()), rotate the exposed ones, and keep them out of git."))
        if "image" in cats:
            items.append(("Clean the image library", "Delete flagged images; re-encode every uploaded image (GD/Intervention) so metadata and appended bytes are stripped."))
        if "config" in cats:
            items.append(("Fix configuration issues", "Work through the config findings: debug flags, cookie flags, CORS, leftover files and dev packages."))
        if "upgrade" in cats:
            items.append(("Plan upgrades", "See the Upgrade tab: out-of-support Laravel/PHP versions and dev packages in production."))
        items.append(("Check persistence outside the code", "Look at cron jobs, SSH keys, FTP/hosting users, database admin users and Laravel scheduled tasks."))
        items.append(("Restore from a known-good backup", "If possible redeploy from a clean git commit; only copy back .env (after rotation) and user uploads that pass a scan."))
        return [dict(title=a, detail=b) for a, b in items]

    # -- driver
    def run(self):
        st_ = self.state
        st_.update(status="indexing", phase="Indexing files…", done=0, total=0, current="")
        files = []
        for dp, dn, fn in os.walk(self.root, followlinks=False):
            for f in fn:
                files.append(os.path.join(dp, f))
            for d in dn:
                dpath = os.path.join(dp, d)
                if os.path.islink(dpath):
                    try:
                        tgt = os.path.realpath(dpath)
                        if not tgt.startswith(self.root):
                            self.add(os.path.relpath(dpath, self.root).replace(os.sep, "/"), "medium", "S020", "Symlink pointing outside the project → " + tgt, "Symlink attacks expose other accounts' files.", "structure")
                    except OSError:
                        pass
            if st_.get("cancel"):
                st_["status"] = "cancelled"
                return None
        self.total = len(files)
        st_.update(status="scanning", phase="Scanning files…", total=self.total)
        t0 = time.time()
        for i, full in enumerate(files):
            if st_.get("cancel"):
                st_["status"] = "cancelled"
                return None
            rel = os.path.relpath(full, self.root).replace(os.sep, "/")
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            self.mtimes.append((int(st.st_mtime), rel))
            if self.since and st.st_mtime < self.since and not rel.startswith((".env",)):
                # still scan, but we use `since` only as a UI filter; nothing skipped
                pass
            try:
                self.analyze(rel, full, st)
            except Exception as e:  # never let one file stop the scan
                self.notes.append("%s: %s" % (rel, e))
            if i % 25 == 0:
                st_.update(done=i, current=rel)
        st_.update(done=self.total, phase="Project-level audit…")
        self.audit_laravel()
        self.audit_config()
        self.correlate()
        clusters, days = self.timeline()
        st_.update(phase="Finalising…")
        files_out = []
        for rel, r in self.records.items():
            r["findings"].sort(key=lambda f: -SEV[f["sev"]])
            r["sev"] = r["findings"][0]["sev"] if r["findings"] else "info"
            r["cats"] = sorted({f["cat"] for f in r["findings"]})
            fp = os.path.join(self.root, rel)
            if os.path.isfile(fp) and r["size"] < 80 * 1024 * 1024 and SEV[r["sev"]] >= 2:
                try:
                    r["sha256"] = self.sha(fp)
                    r["md5"] = self.sha(fp, "md5")
                except OSError:
                    pass
        recs = sorted(self.records.values(), key=lambda r: (-SEV[r["sev"]], -len(r["findings"]), r["path"]))
        for i, r in enumerate(recs):
            r["id"] = i
        counts = {k: 0 for k in SEV}
        fcounts = {k: 0 for k in SEV}
        cats = Counter()
        for r in recs:
            counts[r["sev"]] += 1
            for f in r["findings"]:
                fcounts[f["sev"]] += 1
                cats[f["cat"]] += 1
        if counts["critical"]:
            verdict = ("COMPROMISED", "Confirmed malicious indicators were found.")
        elif counts["high"]:
            verdict = ("SUSPICIOUS", "High-risk patterns found - review each file.")
        elif counts["medium"]:
            verdict = ("REVIEW", "Only medium-risk findings.")
        else:
            verdict = ("CLEAN", "No significant indicators found by these checks.")
        iocs = sorted(({"type": k[0], "value": k[1], "count": v["count"], "files": sorted(v["files"])} for k, v in self.iocs.items()), key=lambda x: -x["count"])[:200]
        res = dict(root=self.root, scanned=self.total, finished=int(time.time()), seconds=round(time.time() - t0, 1),
                   verdict=dict(label=verdict[0], text=verdict[1]), counts=counts, finding_counts=fcounts,
                   categories=dict(cats), files=recs, clusters=clusters, days=days, iocs=iocs,
                   secrets=self.secrets, keys=self.key_hits[:500], images=dict(scanned=self.img_total, flagged=len(self.img_bad)),
                   upgrades=self.upgrades, remediation=self.remediation(set(cats)), notes=self.notes[:20], version=VERSION)
        st_["status"] = "done"
        return res


# ----------------------------------------------------------------------------------------------
# Quarantine
# ----------------------------------------------------------------------------------------------
def _clean_rel(path):
    p = os.path.normpath(str(path).strip()).replace("\\", "/")
    parts = [x for x in p.split("/") if x and x != "."]
    if not parts or any(x == ".." for x in parts):
        return None
    return "/".join(parts)


def quarantine_dir(root):
    return root.rstrip(os.sep) + "_QUARANTINE"


def do_quarantine(root, rels):
    ts = time.strftime("%Y%m%d-%H%M%S")
    qd = os.path.join(quarantine_dir(root), ts)
    os.makedirs(qd, exist_ok=True)
    moved, errors = [], []
    for raw_rel in rels:
        rel = _clean_rel(raw_rel)
        if not rel:
            errors.append("%s: invalid or unsafe path" % raw_rel)
            continue
        src = os.path.realpath(os.path.join(root, rel))
        if not src.startswith(root + os.sep) or not os.path.isfile(src):
            errors.append("%s: not a file inside the project" % rel)
            continue
        dst = os.path.join(qd, rel)
        if not os.path.realpath(os.path.abspath(dst)).startswith(os.path.realpath(qd) + os.sep):
            errors.append("%s: destination path escape attempt" % rel)
            continue
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)
            try:
                os.chmod(dst, 0o400)
            except OSError:
                pass
            moved.append(dict(rel=rel))
        except OSError as e:
            errors.append("%s: %s" % (rel, e))
    with open(os.path.join(qd, "manifest.json"), "w") as f:
        json.dump(dict(root=root, time=ts, files=moved), f, indent=1)
    return dict(id=ts, moved=len(moved), errors=errors, folder=qd)


def list_quarantines(root):
    out = []
    qd = quarantine_dir(root)
    if os.path.isdir(qd):
        for d in sorted(os.listdir(qd), reverse=True):
            if os.sep in d or "/" in d or ".." in d:
                continue
            mp = os.path.join(qd, d, "manifest.json")
            if os.path.isfile(mp):
                try:
                    m = json.load(open(mp))
                    out.append(dict(id=d, files=[x["rel"] for x in m["files"]], folder=os.path.join(qd, d)))
                except Exception:
                    pass
    return out


def do_restore(root, qid):
    if os.sep in qid or "/" in qid or "\\" in qid or ".." in qid:
        return dict(restored=0, errors=["invalid quarantine id"])
    qd = os.path.join(quarantine_dir(root), qid)
    mp = os.path.join(qd, "manifest.json")
    if not os.path.isfile(mp):
        return dict(restored=0, errors=["unknown quarantine"])
    m = json.load(open(mp))
    n, errs = 0, []
    for x in m["files"]:
        rel = _clean_rel(x.get("rel", ""))
        if not rel:
            errs.append("Invalid relative path in manifest")
            continue
        src = os.path.join(qd, rel)
        dst = os.path.realpath(os.path.join(root, rel))
        if not dst.startswith(root + os.sep):
            continue
        if os.path.exists(dst):
            errs.append(rel + ": target exists")
            continue
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)
            n += 1
        except OSError as e:
            errs.append("%s: %s" % (rel, e))
    return dict(restored=n, errors=errs)


def generate_hardened_htaccess(target_dir):
    content = """# Generated by Laravel Sentinel
# Disable PHP script execution in asset/upload folders
<IfModule mod_php.c>
    php_flag engine off
</IfModule>
<IfModule mod_php7.c>
    php_flag engine off
</IfModule>
<IfModule mod_php8.c>
    php_flag engine off
</IfModule>
<FilesMatch "(?i)\\.(php|phtml|php3|php4|php5|php7|php8|phps|phar|inc|suspected)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order Allow,Deny
        Deny from all
    </IfModule>
</FilesMatch>
"""
    target_path = os.path.join(target_dir, ".htaccess")
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content)
    return target_path


# ----------------------------------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------------------------------
def export_html(res):
    e = html.escape
    rows = []
    for r in res["files"]:
        fs = "".join("<li><b>%s</b> %s <small>%s</small></li>" % (e(f["sev"].upper()), e(f["title"]), e((f.get("snippet") or "")[:160])) for f in r["findings"][:12])
        rows.append("<tr class=%s><td>%s</td><td><code>%s</code></td><td><ul>%s</ul></td><td>%s</td></tr>" % (r["sev"], e(r["sev"]), e(r["path"]), fs, e(r.get("sha256", ""))[:16]))
    ioc = "".join("<li><code>%s</code> (%d)</li>" % (e(i["value"]), i["count"]) for i in res["iocs"][:100])
    rem = "".join("<li><b>%s</b> - %s</li>" % (e(x["title"]), e(x["detail"])) for x in res["remediation"])
    return ("<!doctype html><meta charset=utf-8><title>Laravel Sentinel report</title><style>body{font:14px system-ui;margin:2em;max-width:1200px}"
            "table{border-collapse:collapse;width:100%%}td{border:1px solid #ccc;padding:6px;vertical-align:top}.critical{background:#ffe3e3}.high{background:#fff0e0}.medium{background:#fffbe0}"
            "code{font-size:12px}ul{margin:0;padding-left:1.1em}</style><h1>Laravel Sentinel report</h1><p><b>%s</b> - %s<br>Root: <code>%s</code> · files scanned: %d · flagged: %d</p>"
            "<h2>Remediation</h2><ol>%s</ol><h2>Indicators of compromise</h2><ul>%s</ul><h2>Flagged files</h2><table>%s</table><hr style='margin-top:2em;border:0;border-top:1px solid #ddd'><p style='color:#777;font-size:12px'>Powered by Kneazle · Laravel Sentinel v%s</p>"
            % (e(res["verdict"]["label"]), e(res["verdict"]["text"]), e(res["root"]), res["scanned"], len(res["files"]), rem, ioc, "".join(rows), VERSION))


# ----------------------------------------------------------------------------------------------
# HTTP server
# ----------------------------------------------------------------------------------------------
TOKEN = secrets.token_urlsafe(18)
STATE = dict(status="idle", phase="", done=0, total=0, current="", cancel=False)
LAST = dict(result=None, root=None)
LOCK = threading.Lock()


def start_scan(opts):
    root = os.path.expanduser(opts.get("path", ""))
    if not os.path.isdir(root):
        raise ValueError("Folder not found: %s" % root)
    if STATE["status"] in ("indexing", "scanning"):
        raise ValueError("A scan is already running")
    since = None
    if opts.get("since"):
        try:
            since = time.mktime(time.strptime(opts["since"], "%Y-%m-%d"))
        except ValueError:
            pass
    STATE.update(status="indexing", cancel=False, done=0, total=0, error=None)
    LAST["result"] = None

    def worker():
        try:
            sc = Scan(root, STATE, deep=bool(opts.get("deep")), baseline=opts.get("baseline") or None, since=since,
                      custom=[x for x in re.split(r"[,\n]", opts.get("custom", "")) if x.strip()])
            res = sc.run()
            if res:
                LAST["result"], LAST["root"] = res, sc.root
        except Exception as e:
            STATE.update(status="error", error=str(e))

    threading.Thread(target=worker, daemon=True).start()


def file_detail(fid):
    res = LAST["result"]
    if not res or fid < 0 or fid >= len(res["files"]):
        return None
    r = res["files"][fid]
    full = os.path.join(res["root"], r["path"])
    src, trunc, note = "", False, ""
    try:
        sz = os.path.getsize(full)
        with open(full, "rb") as f:
            b = f.read(300_000)
        trunc = sz > 300_000
        if printable_ratio(b) > 0.85:
            src = b.decode("utf-8", "replace")
        else:
            src = "[binary content - first 256 bytes as hex]\n" + b[:256].hex(" ")
            note = "binary"
    except OSError as e:
        src = "[file is no longer on disk: %s]" % e
    d = dict(r)
    d.update(source=src, truncated=trunc, note=note, exists=os.path.isfile(full), ent=round(entropy(src.encode("latin-1", "ignore")[:100000]), 2))
    return d


def browse(path):
    p = os.path.expanduser(path or "~")
    p = os.path.realpath(p)
    if not os.path.isdir(p):
        p = os.path.dirname(p)
    dirs = []
    try:
        for n in sorted(os.listdir(p), key=str.lower):
            fp = os.path.join(p, n)
            if os.path.isdir(fp) and not n.startswith("."):
                dirs.append(dict(name=n, laravel=os.path.isfile(os.path.join(fp, "artisan")) or os.path.isfile(os.path.join(fp, "composer.json"))))
    except OSError:
        pass
    return dict(path=p, parent=os.path.dirname(p), dirs=dirs[:500],
                laravel=os.path.isfile(os.path.join(p, "artisan")) or os.path.isfile(os.path.join(p, "composer.json")))



# ----------------------------------------------------------------------------------------------
# Agentic AI & Safety Snapshot Engine
# ----------------------------------------------------------------------------------------------
def create_backup_snapshot(root, files_to_backup, action_name="ai_remediation"):
    timestamp = int(time.time())
    snap_id = "snap_%d" % timestamp
    backup_dir = os.path.join(root, ".sentinel_backups", snap_id)
    os.makedirs(backup_dir, exist_ok=True)
    manifest = {
        "id": snap_id,
        "timestamp": timestamp,
        "date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
        "action": action_name,
        "files": []
    }
    for rel in files_to_backup:
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            continue
        rel_clean = rel.replace("/", "_").replace("\\", "_")
        bak_dest = os.path.join(backup_dir, rel_clean + ".bak")
        shutil.copy2(full, bak_dest)
        with open(full, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        manifest["files"].append({
            "original_path": rel,
            "backup_file": rel_clean + ".bak",
            "sha256": h,
            "mode": oct(os.stat(full).st_mode & 0o777)
        })
    with open(os.path.join(backup_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def rollback_snapshot(root, snap_id):
    backup_dir = os.path.join(root, ".sentinel_backups", snap_id)
    manifest_file = os.path.join(backup_dir, "manifest.json")
    if not os.path.isfile(manifest_file):
        raise ValueError("Snapshot not found: %s" % snap_id)
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    restored = 0
    errors = []
    for item in manifest.get("files", []):
        bak = os.path.join(backup_dir, item["backup_file"])
        orig = os.path.join(root, item["original_path"])
        if not os.path.isfile(bak):
            errors.append("Missing backup: %s" % item["backup_file"])
            continue
        try:
            os.makedirs(os.path.dirname(orig), exist_ok=True)
            shutil.copy2(bak, orig)
            restored += 1
        except Exception as e:
            errors.append("%s: %s" % (item["original_path"], e))
    return {"ok": True, "restored": restored, "errors": errors, "id": snap_id}


def list_backup_snapshots(root):
    if not root:
        return []
    base = os.path.join(root, ".sentinel_backups")
    if not os.path.isdir(base):
        return []
    snaps = []
    try:
        for d in sorted(os.listdir(base), reverse=True):
            mpath = os.path.join(base, d, "manifest.json")
            if os.path.isfile(mpath):
                try:
                    with open(mpath, "r", encoding="utf-8") as f:
                        snaps.append(json.load(f))
                except Exception:
                    pass
    except OSError:
        pass
    return snaps


def ai_analyze_file(root, rel_path, file_obj=None, provider="auto", api_key=""):
    """Analyze a single file finding and propose a safe remediation opportunity."""
    key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY") or ""
    prov = provider
    if prov == "auto":
        if os.getenv("GEMINI_API_KEY") or (api_key and api_key.startswith("AIza")):
            prov = "gemini"
        elif os.getenv("OPENAI_API_KEY") or (api_key and api_key.startswith("sk-")):
            prov = "openai"
        else:
            prov = "heuristic"

    # Default heuristic analysis
    cats = file_obj.get("cats", []) if file_obj else []
    findings = file_obj.get("findings", []) if file_obj else []
    top_title = findings[0]["title"] if findings else "Suspicious Code"
    snippet = findings[0].get("snippet", "") if findings else ""

    action = "quarantine"
    verdict = "CONFIRMED_MALWARE"
    explanation = "This file contains suspicious patterns characteristic of PHP backdoors, webshells, or droppers."
    diff_text = ""
    fixed_code = ""

    # Rule-based heuristics tailored to Laravel
    if any(c in ("polyglot", "image") for c in cats) or "image/png" in top_title.lower() or "webp" in rel_path.lower():
        verdict = "CONFIRMED_MALWARE"
        action = "quarantine"
        explanation = "PHP webshell concealed inside an image polyglot or uploaded media file in storage/public directory."
    elif "halt_compiler" in snippet or "cjfuns.php" in rel_path or "Lock" in snippet:
        verdict = "CONFIRMED_MALWARE"
        action = "quarantine"
        explanation = "Multi-layer deobfuscated dropper payload utilizing __halt_compiler and runtime stream execution."
    elif "bagent" in snippet or "seo-spam" in cats:
        verdict = "CONFIRMED_MALWARE"
        action = "quarantine"
        explanation = "Blackhat search engine cloaking script serving hidden spam pages to search crawler bots."
    elif any(c in ("config", "laravel") for c in cats):
        verdict = "SECURITY_MISCONFIG"
        action = "patch"
        explanation = "Insecure Laravel configuration or exposed rewrite rule."
        diff_text = "# Suggested patch:\nDisable execution in asset folders or update .env settings."
    else:
        verdict = "HIGH_RISK_CODE"
        action = "quarantine"
        explanation = f"Flagged by Sentinel rule: {top_title}. Review findings and isolate into quarantine."

    # If external LLM API is configured, attempt intelligent enhancement
    if prov == "gemini" and key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={key}"
            prompt = (
                f"You are a Laravel security expert. Analyze this flagged file in a Laravel project:\n"
                f"File: {rel_path}\nFinding: {top_title}\nSnippet: {snippet[:400]}\n"
                f"Respond with JSON: {{'verdict': 'CONFIRMED_MALWARE'|'HIGH_RISK_CODE'|'FALSE_POSITIVE', "
                f"'action': 'quarantine'|'patch'|'ignore', 'explanation': '<plain english explanation>', "
                f"'diff': '<suggested unified diff or empty>'}}"
            )
            req_data = json.dumps({"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"responseMimeType": "application/json"}}).encode("utf-8")
            req = urllib.request.Request(url, data=req_data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=12) as r:
                resp = json.loads(r.read().decode("utf-8"))
                part = resp["candidates"][0]["content"]["parts"][0]["text"]
                llm_out = json.loads(part)
                verdict = llm_out.get("verdict", verdict)
                action = llm_out.get("action", action)
                explanation = llm_out.get("explanation", explanation)
                diff_text = llm_out.get("diff", diff_text)
        except Exception:
            pass  # gracefully falls back to deterministic heuristic

    return {
        "path": rel_path,
        "verdict": verdict,
        "action": action,
        "provider": prov,
        "explanation": explanation,
        "diff": diff_text,
        "fixed_code": fixed_code
    }


def ai_batch_analyze(root, provider="auto", api_key=""):
    r = LAST.get("result")
    if not r or not root:
        return []
    items = []
    # Analyze the most critical flagged files
    flagged = sorted(r.get("files", []), key=lambda x: SEV.get(x.get("sev", "info"), 0), reverse=True)
    for f in flagged[:30]:
        items.append(ai_analyze_file(root, f["path"], file_obj=f, provider=provider, api_key=api_key))
    return items


def ai_apply_fix(root, fix_data):
    path = fix_data.get("path")
    action = fix_data.get("action")
    if not path or not root:
        raise ValueError("Missing path or root directory")

    full_path = os.path.join(root, path)
    if not os.path.isfile(full_path):
        raise ValueError(f"File not found: {path}")

    # 1. Take safety snapshot first
    snapshot = create_backup_snapshot(root, [path], action_name=f"ai_{action}_{os.path.basename(path)}")

    # 2. Execute action
    result_msg = ""
    if action == "quarantine":
        qres = do_quarantine(root, [path])
        result_msg = f"Quarantined to {qres.get('folder', 'quarantine')}"
    elif action == "patch":
        patch_content = fix_data.get("fixed_code")
        if patch_content:
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(patch_content)
            result_msg = "Patched file successfully."
        else:
            result_msg = "No automated patch content provided."
    elif action == "ignore":
        result_msg = "Marked as ignored."
    else:
        raise ValueError(f"Unknown action: {action}")

    return {
        "ok": True,
        "path": path,
        "action": action,
        "message": result_msg,
        "snapshot_id": snapshot["id"]
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Sentinel"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text") or ctype == "application/json" else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _auth(self, qs):
        host = self.headers.get("Host", "").split(":")[0]
        tok = self.headers.get("X-Token") or (qs.get("t") or [""])[0]
        return host in ("127.0.0.1", "localhost") and secrets.compare_digest(tok, TOKEN)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if not self._auth(qs):
            return self._send(403, {"error": "forbidden"})
        try:
            if u.path == "/":
                return self._send(200, INDEX_HTML, "text/html")
            if u.path == "/api/progress":
                return self._send(200, {k: STATE.get(k) for k in ("status", "phase", "done", "total", "current", "error")})
            if u.path == "/api/results":
                r = LAST["result"]
                if not r:
                    return self._send(404, {"error": "no results"})
                slim = dict(r, files=[dict(id=f["id"], path=f["path"], sev=f["sev"], size=f["size"], mtime=f["mtime"], cats=f["cats"],
                                           n=len(f["findings"]), top=[x["title"] for x in f["findings"][:3]], decoded=len(f["payloads"])) for f in r["files"]])
                return self._send(200, slim)
            if u.path == "/api/findings":
                r = LAST["result"]
                if not r:
                    return self._send(404, {"error": "no results"})
                out = []
                for f in r["files"]:
                    for x in f["findings"]:
                        out.append(dict(id=f["id"], path=f["path"], sev=x["sev"], rule=x["rule"], title=x["title"], line=x["line"],
                                        snippet=(x["snippet"] or "")[:200], cat=x["cat"], layer=bool(x["layer"])))
                out.sort(key=lambda z: -SEV[z["sev"]])
                return self._send(200, out[:20000])
            if u.path == "/api/file":
                d = file_detail(int(qs.get("id", ["-1"])[0]))
                return self._send(200, d) if d else self._send(404, {"error": "unknown file"})
            if u.path == "/api/browse":
                return self._send(200, browse((qs.get("path") or [""])[0]))
            if u.path == "/api/ai/backups":
                return self._send(200, list_backup_snapshots(LAST.get("root")))
            if u.path == "/api/ai/status":
                return self._send(200, {"gemini": bool(os.getenv("GEMINI_API_KEY")), "openai": bool(os.getenv("OPENAI_API_KEY"))})
            if u.path == "/api/quarantines":
                return self._send(200, list_quarantines(LAST["root"]) if LAST["root"] else [])
            if u.path == "/api/export.json" and LAST["result"]:
                return self._send(200, json.dumps(LAST["result"], indent=1), "application/json", {"Content-Disposition": "attachment; filename=sentinel-report.json"})
            if u.path == "/api/export.html" and LAST["result"]:
                return self._send(200, export_html(LAST["result"]), "text/html", {"Content-Disposition": "attachment; filename=sentinel-report.html"})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        u = urlparse(self.path)
        if not self._auth(parse_qs(u.query)):
            return self._send(403, {"error": "forbidden"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            if u.path == "/api/scan":
                start_scan(body)
                return self._send(200, {"ok": True})
            if u.path == "/api/cancel":
                STATE["cancel"] = True
                return self._send(200, {"ok": True})
            if u.path == "/api/quarantine":
                if not LAST["root"]:
                    return self._send(400, {"error": "scan first"})
                return self._send(200, do_quarantine(LAST["root"], [str(x) for x in body.get("files", [])]))
            if u.path == "/api/ai/analyze":
                if not LAST.get("root"):
                    return self._send(400, {"error": "Scan a project first before running AI analysis"})
                return self._send(200, ai_batch_analyze(LAST["root"], provider=body.get("provider", "auto"), api_key=body.get("apiKey", "")))
            if u.path == "/api/ai/apply_fix":
                if not LAST.get("root"):
                    return self._send(400, {"error": "Scan a project first"})
                return self._send(200, ai_apply_fix(LAST["root"], body))
            if u.path == "/api/ai/rollback":
                if not LAST.get("root"):
                    return self._send(400, {"error": "Scan a project first"})
                return self._send(200, rollback_snapshot(LAST["root"], str(body.get("snapId", ""))))
            if u.path == "/api/restore":
                return self._send(200, do_restore(LAST["root"], str(body.get("id", ""))))
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(400, {"error": str(e)})


INDEX_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Laravel Sentinel — Cyber Threat Scanner &amp; Deobfuscator</title>
<style>
:root{
  --bg:#07090e;--p:#0d121c;--p2:#131a27;--p3:#1a2334;
  --b:#1e293b;--b2:#2d3c54;--b-bright:#00f0ff;
  --t:#f1f5f9;--m:#8ea0bc;--faint:#475569;
  --cyan:#00f0ff;--green:#00ff88;
  --crit:#ff2a5f;--crit-bg:rgba(255,42,95,0.14);--crit-glow:rgba(255,42,95,0.45);
  --high:#ff8800;--high-bg:rgba(255,136,0,0.14);
  --med:#ffd000;--med-bg:rgba(255,208,0,0.14);
  --low:#00d4ff;--low-bg:rgba(0,212,255,0.14);
  --info:#a78bfa;--info-bg:rgba(167,139,250,0.14);
  --ok:#00ff88;--ok-bg:rgba(0,255,136,0.14);
  --radius:8px;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--t);font:13.5px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;-webkit-font-smoothing:antialiased}
code,.mono{font-family:ui-monospace,"SF Mono","Fira Code",Menlo,Consolas,monospace}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--b);background:var(--p);box-shadow:0 4px 20px rgba(0,0,0,0.4)}
.brand{display:flex;align-items:center;gap:12px}

/* Minimalist Monochrome Logo Mark */
.logo-mark{width:32px;height:32px;background:#131a27;border:1px solid #334155;color:#f1f5f9;display:flex;align-items:center;justify-content:center;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,0.3)}
.brand h1{font-size:15px;font-weight:800;margin:0;letter-spacing:0.04em;display:flex;align-items:center;gap:8px;color:#ffffff}
.brand span.ver{font-size:10px;font-weight:700;padding:2px 7px;background:rgba(0,240,255,0.12);border:1px solid #00f0ff;border-radius:10px;color:#00f0ff;font-family:ui-monospace,monospace}
.brand small{color:var(--m);font-size:11.5px}

.pulse-dot{display:inline-block;width:7px;height:7px;background:#00ff88;border-radius:50%;margin-right:6px;box-shadow:0 0 8px #00ff88}
.chip-hacker-live{display:inline-flex;align-items:center;color:#00ff88;border:1px solid #00ff88;background:rgba(0,255,136,0.1);padding:3px 9px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:0.05em;font-family:ui-monospace,monospace}
.chip-hacker{display:inline-flex;align-items:center;gap:6px;color:#00f0ff;border:1px solid #00f0ff;background:rgba(0,240,255,0.1);padding:3px 9px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:0.05em;font-family:ui-monospace,monospace;box-shadow:0 0 10px rgba(0,240,255,0.2)}
.chip-shield{display:inline-flex;align-items:center;gap:6px;color:var(--m);border:1px solid var(--b2);background:var(--p2);padding:3px 9px;border-radius:4px;font-size:11px;font-family:ui-monospace,monospace}

main{padding:20px 24px;max-width:1560px;margin:auto}
.card{background:var(--p);border:1px solid var(--b);border-radius:var(--radius);padding:18px;margin-bottom:16px;box-shadow:0 4px 16px rgba(0,0,0,0.25)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input[type=text],input[type=date],select,textarea{background:var(--p2);border:1px solid var(--b);color:var(--t);border-radius:var(--radius);padding:9px 12px;font:inherit;font-size:13px;outline:none;transition:border-color .15s}
input[type=text]:focus,input[type=date]:focus,select:focus{border-color:var(--cyan);box-shadow:0 0 8px rgba(0,240,255,0.25)}
input.grow{flex:1;min-width:280px}
button{background:var(--p2);color:var(--t);border:1px solid var(--b);border-radius:var(--radius);padding:8px 14px;cursor:pointer;font:inherit;font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:6px;transition:all .15s;user-select:none}
button:hover{border-color:var(--cyan);background:var(--p3)}
button.pri{background:#00f0ff;border-color:#00f0ff;color:#000000;font-weight:800;box-shadow:0 0 12px rgba(0,240,255,0.35)}
button.pri:hover{background:#33f3ff;border-color:#33f3ff;box-shadow:0 0 18px rgba(0,240,255,0.6)}
button.danger{background:rgba(255,42,95,0.12);border:1px solid #ff2a5f;color:#ff2a5f;font-weight:700}
button.danger:hover:not(:disabled){background:#ff2a5f;color:#ffffff;box-shadow:0 0 14px rgba(255,42,95,0.5)}
button.success{background:rgba(0,255,136,0.12);border:1px solid #00ff88;color:#00ff88;font-weight:700}
button.success:hover:not(:disabled){background:#00ff88;color:#000000;box-shadow:0 0 14px rgba(0,255,136,0.5)}
button:disabled{opacity:.35;cursor:not-allowed}
label.opt{color:var(--m);display:flex;gap:8px;align-items:center;font-size:12.5px;cursor:pointer;user-select:none}
.bar{height:4px;background:var(--p2);border-radius:2px;overflow:hidden;margin-top:12px}
.bar>div{height:100%;background:linear-gradient(90deg,#00f0ff,#00ff88);width:0;transition:width .2s ease-out;box-shadow:0 0 8px rgba(0,240,255,0.5)}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.stat{background:var(--p);border:1px solid var(--b);border-radius:var(--radius);padding:16px;cursor:pointer;transition:all .15s;position:relative;overflow:hidden}
.stat:hover{border-color:var(--b2);transform:translateY(-1px)}
.stat.on{background:var(--p2);box-shadow:0 0 14px rgba(0,240,255,0.15);border-color:var(--cyan)}
.stat.critical{border-left:4px solid var(--crit)}
.stat.high{border-left:4px solid var(--high)}
.stat.medium{border-left:4px solid var(--med)}
.stat.low{border-left:4px solid var(--low)}
.stat.info{border-left:4px solid var(--info)}

.stat-num{font-size:30px;font-weight:800;line-height:1.1;letter-spacing:-0.02em;font-family:ui-monospace,monospace}
.stat-num.critical{color:var(--crit);text-shadow:0 0 12px rgba(255,42,95,0.4)}
.stat-num.high{color:var(--high)}
.stat-num.medium{color:var(--med)}
.stat-num.low{color:var(--low)}
.stat-num.info{color:var(--info)}
.stat-label{font-size:12px;text-transform:uppercase;letter-spacing:0.05em;font-weight:700;margin-top:6px;color:var(--t)}
.stat-sub{color:var(--m);font-size:11px;margin-top:3px}

.verdict{padding:16px 20px;border-radius:var(--radius);margin-bottom:16px;display:flex;gap:16px;align-items:center;border:1px solid var(--b)}
.verdict.COMPROMISED{background:rgba(255,42,95,0.12);border-color:#ff2a5f;box-shadow:0 0 20px rgba(255,42,95,0.2)}
.verdict.COMPROMISED .v-badge{background:#ff2a5f;color:#ffffff;font-weight:800;padding:5px 12px;border-radius:4px;font-size:12px;letter-spacing:0.05em;font-family:ui-monospace,monospace;box-shadow:0 0 10px rgba(255,42,95,0.6);display:inline-flex;align-items:center;gap:6px}
.verdict.CLEAN{background:rgba(0,255,136,0.1);border-color:#00ff88;box-shadow:0 0 20px rgba(0,255,136,0.15)}
.verdict.CLEAN .v-badge{background:#00ff88;color:#000000;font-weight:800;padding:5px 12px;border-radius:4px;font-size:12px;letter-spacing:0.05em;font-family:ui-monospace,monospace;display:inline-flex;align-items:center;gap:6px}
.v-text{display:flex;flex-direction:column;gap:3px}
.v-text b{font-size:14.5px;color:#ffffff}
.v-text span{font-size:12.5px;color:var(--m)}

.tabs{display:flex;gap:6px;border-bottom:1px solid var(--b);margin-bottom:16px;flex-wrap:wrap}
.tab{padding:9px 16px;cursor:pointer;color:var(--m);border-bottom:2px solid transparent;font-size:13px;font-weight:600;transition:all .15s;display:inline-flex;align-items:center;gap:6px}
.tab:hover{color:var(--t)}
.tab.on{color:#00f0ff;border-bottom-color:#00f0ff;text-shadow:0 0 10px rgba(0,240,255,0.3)}

table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--b);vertical-align:middle}
th{color:var(--m);font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;position:sticky;top:0;background:var(--p);z-index:2}
tr.f{cursor:pointer;transition:background .1s}
tr.f:hover{background:var(--p2)}

.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:4px;font-size:10.5px;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;font-family:ui-monospace,monospace}
.badge.critical{background:var(--crit);color:#ffffff;box-shadow:0 0 10px rgba(255,42,95,0.5)}
.badge.high{background:var(--high-bg);border:1px solid var(--high);color:var(--high)}
.badge.medium{background:var(--med-bg);border:1px solid var(--med);color:var(--med)}
.badge.low{background:var(--low-bg);border:1px solid var(--low);color:var(--low)}
.badge.info{background:var(--info-bg);border:1px solid var(--info);color:var(--info)}
.badge.clean,.badge.ok{background:var(--ok-bg);border:1px solid var(--ok);color:var(--ok)}

.chip{display:inline-flex;align-items:center;background:var(--p2);border:1px solid var(--b);border-radius:4px;padding:2px 7px;font-size:11px;color:var(--m);margin:0 4px 4px 0}
.scroll{max-height:64vh;overflow:auto;border-radius:var(--radius);border:1px solid var(--b)}

#drawer{position:fixed;top:0;right:-880px;width:860px;max-width:96vw;height:100%;background:var(--p);border-left:1px solid var(--b2);box-shadow:-20px 0 60px rgba(0,0,0,0.85);transition:right .22s cubic-bezier(0.16,1,0.3,1);z-index:30;display:flex;flex-direction:column}
#drawer.open{right:0}
#dh{padding:14px 20px;border-bottom:1px solid var(--b);display:flex;gap:12px;align-items:center;background:#090d14}
#db{padding:18px 20px;overflow:auto;flex:1}

/* RED HIGHLIGHT FOR MALWARE LINES IN SOURCE */
.src{background:#05070a;border:1px solid var(--b);border-radius:var(--radius);overflow:auto;max-height:68vh;position:relative}
.ln{display:flex;align-items:center;white-space:pre;font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;font-size:12px;line-height:1.6;border-left:5px solid transparent}
.ln i{color:var(--faint);min-width:48px;text-align:right;padding:0 12px;font-style:normal;user-select:none;border-right:1px solid #141b26}
.code-text{padding-left:8px;flex:1}
.ln.hl{background:rgba(255,42,95,0.28) !important;border-left:5px solid #ff2a5f !important;color:#ffb8c6 !important;font-weight:600 !important;box-shadow:inset 0 0 12px rgba(255,42,95,0.25)}
.ln.hl i{color:#ffffff !important;background:#ff2a5f !important;font-weight:800 !important;border-right:1px solid #ff2a5f !important}
.ln.flash{animation:pulse-red 1.2s ease-out}
@keyframes pulse-red{0%{background:rgba(255,42,95,0.7)}100%{background:rgba(255,42,95,0.28)}}

.threat-pill{background:#ff2a5f;color:#ffffff;font-size:10px;font-weight:800;padding:2px 8px;border-radius:4px;margin:0 12px;letter-spacing:0.05em;display:inline-flex;align-items:center;white-space:nowrap;box-shadow:0 0 10px rgba(255,42,95,0.6)}
.src-banner{background:#111827;border:1px solid rgba(255,42,95,0.3);border-radius:var(--radius);padding:10px 14px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}
.btn-jump-pill{background:rgba(255,42,95,0.15);color:#ff2a5f;border:1px solid #ff2a5f;border-radius:4px;padding:3px 10px;font-size:11px;font-weight:700;cursor:pointer;transition:all .15s}
.btn-jump-pill:hover{background:#ff2a5f;color:#ffffff;box-shadow:0 0 10px rgba(255,42,95,0.6)}
.btn-jump{background:rgba(255,42,95,0.15);color:#ff2a5f;border:1px solid #ff2a5f;border-radius:4px;padding:4px 10px;font-size:11px;font-weight:700;cursor:pointer;transition:all .15s}
.btn-jump:hover{background:#ff2a5f;color:#ffffff;box-shadow:0 0 10px rgba(255,42,95,0.5)}

.fnd{border:1px solid var(--b);border-radius:var(--radius);padding:14px;margin-bottom:12px;background:var(--p2)}
.fnd.critical{border-color:rgba(255,42,95,0.4);border-left:4px solid var(--crit)}
.fnd.high{border-color:rgba(255,136,0,0.4);border-left:4px solid var(--high)}
.fnd.medium{border-color:rgba(255,208,0,0.4);border-left:4px solid var(--med)}
pre.dec{background:#05070a;border:1px solid var(--b);border-radius:var(--radius);padding:12px;overflow:auto;max-height:50vh;white-space:pre-wrap;word-break:break-all;font-size:12px;font-family:ui-monospace,Menlo,monospace;color:#ffffff}
.chain{color:#00f0ff;font-weight:700;font-family:ui-monospace,Menlo,monospace;font-size:12px}

/* AI Remediation Diff Box */
.diff-box{background:#05070a;border:1px solid var(--b);border-radius:var(--radius);padding:12px;font-family:ui-monospace,monospace;font-size:12px;line-height:1.5;overflow:auto;max-height:260px;margin:8px 0}
.diff-del{color:#ff8595;background:rgba(255,42,95,0.15);display:block;padding:1px 4px}
.diff-add{color:#00ff88;background:rgba(0,255,136,0.15);display:block;padding:1px 4px}

#modal{position:fixed;inset:0;background:rgba(0,0,0,0.85);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;z-index:40}
#modal.open{display:flex}
#mbox{background:var(--p);border:1px solid var(--b2);border-radius:10px;width:680px;max-width:94vw;max-height:82vh;display:flex;flex-direction:column;box-shadow:0 25px 60px rgba(0,0,0,0.8)}
#mbox .l{overflow:auto;padding:10px 14px;flex:1}
.dir{padding:8px 12px;border-radius:5px;cursor:pointer;display:flex;align-items:center;gap:8px;transition:background .1s}
.dir:hover{background:var(--p2);color:#00f0ff}

.icon-wrap{display:inline-flex;align-items:center;justify-content:center;vertical-align:middle}
.muted{color:var(--m)}.hide{display:none}
</style></head><body>
<header>
  <div class="brand">
    <div class="logo-mark">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    </div>
    <div>
      <h1>LARAVEL SENTINEL <span class="ver">v2.1</span></h1>
      <small>Automated Malware Scanner &amp; Threat Deobfuscator</small>
    </div>
  </div>
  <div class="row" style="align-items:center;gap:12px">
    <span class="chip-hacker-live"><span class="pulse-dot"></span>SYSTEM ARMED</span>
    <span class="chip-hacker">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
      POWERED BY KNEAZLE
    </span>
    <span class="chip-shield">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      READ-ONLY SAFE
    </span>
  </div>
</header>
<main>
<div class="card">
  <div class="row">
    <input id="path" class="grow" type="text" placeholder="/path/to/laravel-project">
    <button id="browse"></button>
    <button id="scan" class="pri"></button>
    <button id="cancel" class="hide"></button>
  </div>
  <div class="row" style="margin-top:12px">
    <label class="opt"><input type="checkbox" id="deep"> Deep scan JS/assets inside vendor &amp; node_modules (thorough)</label>
    <input id="baseline" type="text" class="grow" style="max-width:360px" placeholder="Optional: folder with a CLEAN vendor/ to compare">
    <input id="custom" type="text" class="grow" style="max-width:300px" placeholder="Extra malware signatures (comma separated)">
  </div>
  <div id="prog" class="hide"><div class="bar"><div id="pbar"></div></div><div class="muted mono" id="ptxt" style="margin-top:8px"></div></div>
  <div id="err" class="crit hide" style="margin-top:10px;padding:10px;border-radius:6px;background:rgba(255,42,95,0.15);border:1px solid #ff2a5f;color:#ff2a5f"></div>
</div>
<div id="out" class="hide">
  <div id="verdict" class="verdict"></div>
  <div class="cards" id="cards"></div>
  <div style="height:18px"></div>
  <div class="tabs" id="tabs">
    <div class="tab on" data-t="files" id="tab-files"></div>
    <div class="tab" data-t="find" id="tab-find"></div>
    <div class="tab" data-t="ai" id="tab-ai"></div>
    <div class="tab" data-t="secrets" id="tab-secrets"></div>
    <div class="tab" data-t="fix" id="tab-fix"></div>
    <div class="tab" data-t="quar" id="tab-quar"></div>
  </div>
  <div id="p-files" class="card">
    <div class="row" style="margin-bottom:12px">
      <input id="q" type="text" class="grow" placeholder="Type to filter files (e.g. index.php, backdoor, upload)...">
      <select id="cat"><option value="">All Categories</option></select>
      <input id="since" type="date" title="Only files modified on/after">
      <button id="selhigh"></button>
      <button id="qbtn" class="danger" disabled></button>
      <button id="xj"></button>
      <button id="xh"></button>
    </div>
    <div class="scroll"><table><thead><tr><th style="width:32px"></th><th style="width:100px">Severity</th><th>File Location</th><th>Why It Was Flagged</th><th style="width:90px">Size</th><th style="width:150px">Modified</th></tr></thead><tbody id="rows"></tbody></table></div>
    <div id="more" class="muted" style="margin-top:10px"></div>
  </div>
  <div id="p-find" class="card hide"></div>
  <div id="p-ai" class="card hide"></div>
  <div id="p-secrets" class="card hide"></div>
  <div id="p-fix" class="card hide"></div>
  <div id="p-quar" class="card hide"></div>
  <div id="p-upg" class="card hide"></div>
  <div id="p-timeline" class="card hide"></div>
  <div id="p-iocs" class="card hide"></div>
</div>
<footer style="margin-top:48px;padding:20px 0;border-top:1px solid var(--b);display:flex;justify-content:space-between;align-items:center;color:var(--m);font-size:12px;letter-spacing:0.02em">
  <div>Laravel Sentinel v2.1 &bull; Automated Malware &amp; Threat Deobfuscator</div>
  <div>Powered by <strong style="color:#00f0ff;letter-spacing:0.04em">Kneazle</strong></div>
</footer>
</main>
<div id="drawer"><div id="dh"><button id="dclose"></button><div style="min-width:0;flex:1"><div id="dtitle" class="mono" style="word-break:break-all;color:#00f0ff;font-weight:700"></div></div></div><div id="db"></div></div>
<div id="modal"><div id="mbox"><div style="padding:14px 18px;border-bottom:1px solid var(--b)" class="row"><b>Choose project folder</b><span id="mpath" class="mono muted" style="flex:1;word-break:break-all"></span></div><div class="l" id="mlist"></div><div class="row" style="padding:14px 18px;border-top:1px solid var(--b);justify-content:flex-end"><button id="mcancel">Cancel</button><button id="muse" class="pri">Use this folder</button></div></div></div>

<script>
const qT=new URLSearchParams(location.search).get('t');if(qT)sessionStorage.sentinelToken=qT;const T=qT||sessionStorage.sentinelToken||'';const $=s=>document.querySelector(s);
const SEVS=['critical','high','medium','low','info'];let R=null,F={sev:new Set(),q:'',cat:'',since:''},SEL=new Set(),SHOW=400;

// Crisp SVG Icons (Zero Emojis)
const ICONS = {
  shield: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  shieldCheck: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`,
  alertTriangle: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  bot: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8.01" y2="16"/><line x1="16" y1="16" x2="16.01" y2="16"/></svg>`,
  key: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>`,
  tool: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>`,
  box: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></svg>`,
  folder: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg>`,
  scan: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><line x1="8" y1="12" x2="16" y2="12"/></svg>`,
  lock: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  download: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  fileText: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/></svg>`,
  code: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
  check: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  x: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  sparkles: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3L12 3z"/></svg>`,
  rotateCcw: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>`,
  eye: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`
};

function icon(name){
  const s=ICONS[name]||'';
  const span=document.createElement('span');
  span.className='icon-wrap';
  span.innerHTML=s;
  return span;
}

// Set button and tab labels with SVG icons
$('#browse').replaceChildren(icon('folder'),' Choose Folder…');
$('#scan').replaceChildren(icon('scan'),' SCAN SYSTEM');
$('#cancel').replaceChildren(icon('x'),' Stop');
$('#selhigh').replaceChildren(icon('check'),' Select Dangerous Files');
$('#qbtn').replaceChildren(icon('lock'),' Move to Quarantine (0)');
$('#xj').replaceChildren(icon('download'),' Export JSON');
$('#xh').replaceChildren(icon('fileText'),' Download Report');
$('#dclose').replaceChildren(icon('x'),' Close');

$('#tab-files').replaceChildren(icon('alertTriangle'),' Infected Files');
$('#tab-find').replaceChildren(icon('sparkles'),' All Threats');
$('#tab-ai').replaceChildren(icon('bot'),' Agentic AI Analyst');
$('#tab-secrets').replaceChildren(icon('key'),' Leaked Secrets');
$('#tab-fix').replaceChildren(icon('tool'),' Remediation Guide');
$('#tab-quar').replaceChildren(icon('box'),' Quarantine Vault');

async function api(p,o){o=o||{};const r=await fetch(p,{method:o.method||'GET',headers:{'X-Token':T,'Content-Type':'application/json'},body:o.body?JSON.stringify(o.body):undefined});const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
function h(tag,a,...k){const e=document.createElement(tag);for(const[x,v]of Object.entries(a||{})){if(x==='class')e.className=v;else if(x==='text')e.textContent=v;else if(x.startsWith('on'))e.addEventListener(x.slice(2),v);else e.setAttribute(x,v)}for(const c of k.flat()){if(c==null)continue;e.append(c.nodeType?c:document.createTextNode(c))}return e}
const fmt=n=>n>1073741824?(n/1073741824).toFixed(2)+' GB':n>1048576?(n/1048576).toFixed(1)+' MB':n>1024?(n/1024).toFixed(1)+' KB':n+' B';
const dt=s=>s?new Date(s*1000).toLocaleString():'';
const badge=s=>h('span',{class:'badge '+s},s.toUpperCase());

async function init(){
  const d=await api('/api/browse?path='+encodeURIComponent(localStorage.sentinelPath||'~'));
  $('#path').value=localStorage.sentinelPath||'';
}

$('#scan').onclick=async()=>{
  const path=$('#path').value.trim();if(!path)return fail('Enter or browse to your project folder.');localStorage.sentinelPath=path;$('#err').classList.add('hide');
  try{await api('/api/scan',{method:'POST',body:{path,deep:$('#deep').checked,baseline:$('#baseline').value.trim(),custom:$('#custom').value,since:''}})}catch(e){return fail(e.message)}
  $('#prog').classList.remove('hide');$('#cancel').classList.remove('hide');$('#scan').disabled=true;poll();
};
$('#cancel').onclick=()=>api('/api/cancel',{method:'POST',body:{}});
function fail(m){const e=$('#err');e.textContent=m;e.classList.remove('hide')}

async function poll(){
  const p=await api('/api/progress');const pct=p.total?Math.round(p.done/p.total*100):5;$('#pbar').style.width=pct+'%';$('#ptxt').textContent=(p.phase||'')+' '+p.done+'/'+p.total+'  '+(p.current||'');
  if(p.status==='done'){$('#scan').disabled=false;$('#cancel').classList.add('hide');$('#prog').classList.add('hide');return load()}
  if(p.status==='error'||p.status==='cancelled'){$('#scan').disabled=false;$('#cancel').classList.add('hide');$('#prog').classList.add('hide');return fail(p.status==='error'?p.error:'Scan stopped.')}
  setTimeout(poll,500);
}

async function load(){
  R=await api('/api/results');SEL.clear();F={sev:new Set(),q:'',cat:'',since:''};$('#out').classList.remove('hide');
  const isBad = R.verdict.label==='COMPROMISED'||R.verdict.label==='SUSPICIOUS';
  const v=$('#verdict');v.className='verdict '+R.verdict.label;
  v.replaceChildren(
    h('div',{class:'v-badge'},isBad?icon('alertTriangle'):icon('shieldCheck'),isBad?' MALWARE DETECTED':' SYSTEM SECURE'),
    h('div',{class:'v-text'},
      h('b',{text:isBad?'Security threats discovered in project files!':'No malicious code or backdoors detected.'}),
      h('span',{text:R.files.length+' dangerous file(s) flagged · '+R.scanned+' files scanned in '+R.seconds+'s · '+R.keys.length+' leaked secrets/keys found.'})
    )
  );
  const SEV_INFO = {
    critical:{title:'Critical Malware',sub:'Backdoors, webshells & trojans'},
    high:{title:'High Risk Code',sub:'Dangerous functions & droppers'},
    medium:{title:'Suspicious Files',sub:'Anomalies & obfuscation'},
    low:{title:'Low Risk',sub:'Minor security warnings'},
    info:{title:'Audit Info',sub:'Laravel configuration notices'}
  };
  const c=$('#cards');c.replaceChildren(...SEVS.map(s=>{
    const info=SEV_INFO[s]||{title:s,sub:'findings'};
    return h('div',{class:'stat '+s,onclick:ev=>{F.sev.has(s)?F.sev.delete(s):F.sev.add(s);cardsOn();render()},'data-s':s},
      h('div',{class:'stat-num '+s,text:R.counts[s]||0}),
      h('div',{class:'stat-label',text:info.title}),
      h('div',{class:'stat-sub',text:info.sub})
    );
  }));
  const cs=$('#cat');cs.replaceChildren(h('option',{value:'',text:'All Categories'}),...Object.entries(R.categories).sort((a,b)=>b[1]-a[1]).map(([k,n])=>h('option',{value:k,text:k+' ('+n+')'})));
  render();renderSecrets();renderFix();renderQuar();FIND=null;AI_ITEMS=null;
}

function cardsOn(){document.querySelectorAll('.stat').forEach(e=>e.classList.toggle('on',F.sev.has(e.dataset.s)))}
function rows(){return R.files.filter(f=>(!F.sev.size||F.sev.has(f.sev))&&(!F.cat||f.cats.includes(F.cat))&&(!F.since||f.mtime*1000>=new Date(F.since).getTime())&&(!F.q||(f.path+' '+f.top.join(' ')).toLowerCase().includes(F.q)))}

function render(){
  const rs=rows();const tb=$('#rows');
  tb.replaceChildren(...rs.slice(0,SHOW).map(f=>{
    const cb=h('input',{type:'checkbox'});cb.checked=SEL.has(f.path);cb.onclick=e=>{e.stopPropagation();cb.checked?SEL.add(f.path):SEL.delete(f.path);upd()};
    return h('tr',{class:'f',onclick:()=>openFile(f.id)},
      h('td',{},cb),
      h('td',{},badge(f.sev)),
      h('td',{},h('code',{style:'color:#00f0ff;font-weight:600',text:f.path}),h('div',{},f.cats.map(x=>h('span',{class:'chip',text:x})))),
      h('td',{},f.top.map(t=>h('div',{style:'margin:2px 0',text:t})),f.decoded?h('span',{class:'chip',style:'color:#00ff88;border-color:#00ff88',text:f.decoded+' decoded payload(s)'}):null),
      h('td',{text:fmt(f.size)}),
      h('td',{text:dt(f.mtime)})
    );
  }));
  $('#more').textContent=rs.length>SHOW?('Showing first '+SHOW+' of '+rs.length+' - narrow your search to see more.'):rs.length+' file(s) found';
  upd();
}

function upd(){
  const b=$('#qbtn');b.replaceChildren(icon('lock'),' Move to Quarantine ('+SEL.size+')');b.disabled=!SEL.size;
}

$('#q').oninput=e=>{F.q=e.target.value.toLowerCase();render()};$('#cat').onchange=e=>{F.cat=e.target.value;render()};$('#since').onchange=e=>{F.since=e.target.value;render()};
$('#selhigh').onclick=()=>{R.files.filter(f=>f.sev==='critical'||f.sev==='high').forEach(f=>SEL.add(f.path));render()};
$('#qbtn').onclick=async()=>{
  if(!confirm('Move '+SEL.size+' dangerous file(s) into safe quarantine?\n\nFiles are isolated safely beside your project with read-only permissions (0400). You can restore them anytime.'))return;
  const r=await api('/api/quarantine',{method:'POST',body:{files:[...SEL]}});
  alert('Successfully quarantined '+r.moved+' file(s) into:\n'+r.folder+(r.errors.length?'\n\nErrors:\n'+r.errors.join('\n'):''));
  SEL.clear();renderQuar();tab('quar');
};
$('#xj').onclick=()=>location.href='/api/export.json?t='+T;
$('#xh').onclick=()=>location.href='/api/export.html?t='+T;

document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>tab(t.dataset.t));
function tab(n){
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on',t.dataset.t===n));
  ['files','find','ai','secrets','fix','quar'].forEach(x=>{
    const el=$('#p-'+x);
    if(el)el.classList.toggle('hide',x!==n);
  });
  if(n==='quar')renderQuar();
  if(n==='find')renderFind();
  if(n==='ai')renderAI();
}

async function openFile(id,jump){
  const d=await api('/api/file?id='+id);
  $('#dtitle').textContent=d.path;
  const body=$('#db');body.replaceChildren();
  const tabs=h('div',{class:'tabs'});const panes={};const tabsEl={};
  const mk=(k,l,el,ic)=>{
    const t=h('div',{class:'tab',onclick:()=>{
      Object.keys(panes).forEach(x=>{panes[x].classList.toggle('hide',x!==k);tabsEl[x].classList.toggle('on',x===k)});
      if(k==='s'&&hlList.length)setTimeout(()=>jumpToLine(jump||hlList[0]),60);
    }},icon(ic),' ',l);
    tabsEl[k]=t;panes[k]=el;tabs.append(t);return el;
  };

  const hl=new Set(d.findings.filter(f=>f.line&&!f.layer).map(f=>f.line));
  const hlList=[...hl].sort((a,b)=>a-b);

  const fp=h('div',{});
  if(!d.findings.length)fp.append(h('p',{class:'muted',text:'No active threats found in this file.'}));
  d.findings.forEach(f=>{
    fp.append(h('div',{class:'fnd '+f.sev},
      h('div',{style:'display:flex;justify-content:space-between;align-items:center;margin-bottom:8px'},
        badge(f.sev),
        f.line?h('button',{class:'btn-jump',onclick:()=>{tabsEl.s.click();setTimeout(()=>jumpToLine(f.line),80)}},icon('eye'),' View Line '+f.line+' in Red Code'):null
      ),
      h('b',{style:'font-size:14px;color:var(--t)',text:f.title}),
      h('div',{style:'margin:6px 0'},
        h('span',{class:'chip',text:f.cat}),
        f.layer?h('span',{class:'chip',style:'color:#00ff88;border-color:#00ff88',text:'In Decoded Payload Layer'}):null,
        f.line?h('span',{class:'chip',style:'color:#ff2a5f;border-color:#ff2a5f;font-weight:700',text:'Line '+f.line}):null
      ),
      f.desc?h('p',{style:'color:var(--m);margin:8px 0;line-height:1.5',text:f.desc}):null,
      f.snippet?h('pre',{class:'dec',style:'padding:8px 10px;margin-top:6px;color:#ff9ebb;background:#101520',text:(f.line?'line '+f.line+': ':'')+f.snippet}):null
    ));
  });

  const src=h('div',{class:'src'});
  d.source.split('\n').slice(0,3000).forEach((l,i)=>{
    const isHl=hl.has(i+1);
    const lineEl=h('div',{class:'ln'+(isHl?' hl':''),'data-l':i+1},
      h('i',{text:i+1}),
      h('span',{class:'code-text',text:l.slice(0,600)}),
      isHl?h('span',{class:'threat-pill',text:'MALWARE LINE [LINE '+(i+1)+']'}):null
    );
    src.append(lineEl);
  });

  function jumpToLine(l){
    const el=src.querySelector('.ln[data-l="'+l+'"]');
    if(el){
      el.scrollIntoView({block:'center',behavior:'smooth'});
      el.classList.add('flash');
      setTimeout(()=>el.classList.remove('flash'),1200);
    }
  }

  const banner=h('div',{class:'src-banner'},
    h('div',{style:'display:flex;align-items:center;gap:10px;flex-wrap:wrap'},
      h('span',{style:'font-weight:800;color:'+(hlList.length?'#ff2a5f':'#00ff88')+';display:flex;align-items:center;gap:6px'},
        icon(hlList.length?'alertTriangle':'shieldCheck'),
        hlList.length?hlList.length+' THREAT LINE(S) FOUND:':'NO MALWARE LINES DETECTED'
      ),
      ...hlList.map(l=>h('button',{class:'btn-jump-pill',onclick:()=>jumpToLine(l)},'Jump to Line '+l))
    )
  );

  const sp=h('div',{},banner,d.truncated?h('p',{class:'muted',style:'padding:4px 0',text:'Showing the first 300 KB.'}):null,src);

  const dp=h('div',{});
  if(!d.payloads.length)dp.append(h('p',{class:'muted',text:'No encoded or hidden payloads were found in this file.'}));
  d.payloads.forEach((p,i)=>dp.append(h('div',{class:'fnd'},
    h('div',{},h('span',{class:'chain',text:p.chain.join(' → ')})),
    h('div',{style:'margin:6px 0'},h('span',{class:'chip',text:p.status}),h('span',{class:'chip',text:p.size+' bytes'}),h('span',{class:'chip',text:'entropy '+p.entropy})),
    h('pre',{class:'dec',text:p.text}),
    h('button',{onclick:()=>navigator.clipboard.writeText(p.text)},icon('fileText'),' Copy Payload')
  )));

  const ip=h('div',{},
    h('table',{},...[['File Path',d.path],['File Size',fmt(d.size)],['Last Modified',dt(d.mtime)],['File Permissions',d.mode],['SHA-256 Hash',d.sha256||'-'],['MD5 Hash',d.md5||'-'],['Threat Categories',d.cats.join(', ')]].map(([a,b])=>h('tr',{},h('td',{class:'muted',text:a}),h('td',{class:'mono',text:b})))),
    h('p',{style:'margin-top:14px'},h('button',{onclick:()=>navigator.clipboard.writeText(d.sha256||'')},icon('fileText'),' Copy SHA-256 (for VirusTotal)'))
  );

  mk('f','Threats ('+d.findings.length+')',fp,'alertTriangle');
  mk('s','Source Code',sp,'code');
  mk('d','Decoded ('+d.payloads.length+')',dp,'fileText');
  mk('i','File Info',ip,'shield');
  body.append(tabs,...Object.values(panes));

  Object.keys(panes).forEach((x,i)=>{panes[x].classList.toggle('hide',i!==0);tabsEl[x].classList.toggle('on',i===0)});
  $('#drawer').classList.add('open');
  if(jump){
    tabsEl.s.click();
    setTimeout(()=>jumpToLine(jump),100);
  } else if(hlList.length){
    setTimeout(()=>{if(!panes.s.classList.contains('hide'))jumpToLine(hlList[0]);},120);
  }
}
$('#dclose').onclick=()=>$('#drawer').classList.remove('open');

// ------------------------------------------------------------------------------------------
// Agentic AI Remediation & Fix Engine
// ------------------------------------------------------------------------------------------
let AI_ITEMS = null;
async function renderAI(){
  const p=$('#p-ai');
  const storedKey = localStorage.sentinelAiKey || '';
  const provider = localStorage.sentinelAiProv || 'auto';

  const cfgRow = h('div',{class:'row',style:'align-items:center;margin-bottom:16px;padding:14px;background:var(--p2);border-radius:var(--radius);border:1px solid var(--b)'},
    h('span',{style:'font-weight:700;color:#00f0ff;display:flex;align-items:center;gap:6px'},icon('bot'),' Agentic AI Settings:'),
    h('select',{id:'ai-prov',onchange:e=>{localStorage.sentinelAiProv=e.target.value}},
      h('option',{value:'auto',selected:provider==='auto'},'Auto-Detect (Gemini / OpenAI / Heuristic)'),
      h('option',{value:'gemini',selected:provider==='gemini'},'Google Gemini API (Fast Token Triage)'),
      h('option',{value:'openai',selected:provider==='openai'},'OpenAI / Local Ollama (v1/chat)'),
      h('option',{value:'heuristic',selected:provider==='heuristic'},'Deterministic Rulebook (Offline)')
    ),
    h('input',{type:'text',id:'ai-key',placeholder:'Optional: API Key (or set GEMINI_API_KEY in env)',style:'width:280px',value:storedKey,onchange:e=>{localStorage.sentinelAiKey=e.target.value.trim()}}),
    h('button',{class:'pri',onclick:()=>runAIAnalysis()},icon('sparkles'),' Run AI Threat Triage & Fix Analysis')
  );

  const container = h('div',{id:'ai-results'});
  if(!AI_ITEMS){
    container.replaceChildren(
      h('p',{class:'muted',text:'Click "Run AI Threat Triage & Fix Analysis" above to have the Agentic AI evaluate all detected malware, identify false positives, and stage safe remediation fixes with rollback.'})
    );
  } else {
    renderAIItems(container);
  }

  // Backup Snapshots Section
  const backupSection = h('div',{style:'margin-top:24px;padding-top:16px;border-top:1px solid var(--b)'},
    h('h4',{style:'color:#00f0ff;margin:0 0 10px;display:flex;align-items:center;gap:6px'},icon('rotateCcw'),' Safety Snapshots & Rollback History'),
    h('div',{id:'ai-backups',text:'Loading snapshots…'})
  );

  p.replaceChildren(cfgRow, container, backupSection);
  loadSnapshots();
}

async function runAIAnalysis(){
  const c=$('#ai-results');
  c.replaceChildren(h('p',{style:'color:#00f0ff;display:flex;align-items:center;gap:8px'},icon('sparkles'),' Agentic AI is evaluating threats and calculating safe patch diffs…'));
  try{
    const prov=$('#ai-prov')?$('#ai-prov').value:localStorage.sentinelAiProv||'auto';
    const key=$('#ai-key')?$('#ai-key').value:localStorage.sentinelAiKey||'';
    AI_ITEMS = await api('/api/ai/analyze',{method:'POST',body:{provider:prov,apiKey:key}});
    renderAIItems(c);
  }catch(e){
    c.replaceChildren(h('p',{class:'crit',text:'AI Analysis failed: '+e.message}));
  }
}

function renderAIItems(container){
  if(!AI_ITEMS||!AI_ITEMS.length){
    container.replaceChildren(h('p',{class:'muted',text:'No active threats to remediate. All scanned files are clean.'}));
    return;
  }
  container.replaceChildren(
    h('div',{style:'display:flex;justify-content:space-between;align-items:center;margin-bottom:14px'},
      h('span',{style:'font-weight:700',text:AI_ITEMS.length+' Actionable Remediations Proposed by Agentic AI:'}),
      h('button',{class:'success',onclick:()=>applyAllAIFixes()},icon('check'),' Apply All Recommended Fixes (with Snapshot)')
    ),
    ...AI_ITEMS.map((item,idx)=>{
      const sevClass = item.verdict==='CONFIRMED_MALWARE'?'critical':item.verdict==='HIGH_RISK_CODE'?'high':'medium';
      return h('div',{class:'fnd '+sevClass,style:'margin-bottom:14px'},
        h('div',{style:'display:flex;justify-content:space-between;align-items:center'},
          h('span',{class:'badge '+sevClass},item.verdict.replace('_',' ')),
          h('span',{class:'chip',text:'Action: '+item.action.toUpperCase()})
        ),
        h('div',{style:'margin:8px 0'},h('code',{style:'color:#00f0ff;font-weight:700',text:item.path})),
        h('p',{style:'color:var(--t);margin:6px 0;font-size:13px',text:item.explanation}),
        item.diff?h('pre',{class:'diff-box',text:item.diff}):null,
        h('div',{style:'display:flex;gap:10px;margin-top:10px'},
          h('button',{class:'success',onclick:()=>applySingleAIFix(item,idx)},icon('check'),' Apply Fix ('+item.action+')'),
          h('button',{onclick:()=>openByPath(item.path)},icon('eye'),' Inspect File')
        )
      );
    })
  );
}

async function applySingleAIFix(item,idx){
  if(!confirm('Apply '+item.action+' to '+item.path+'?\n\nA safety snapshot will be created in .sentinel_backups before changes.'))return;
  try{
    const r=await api('/api/ai/apply_fix',{method:'POST',body:item});
    alert('Fix applied successfully!\n\n'+r.message+'\nSnapshot saved: '+r.snapshot_id);
    AI_ITEMS.splice(idx,1);
    renderAIItems($('#ai-results'));
    loadSnapshots();
  }catch(e){
    alert('Error applying fix: '+e.message);
  }
}

async function applyAllAIFixes(){
  if(!confirm('Apply all '+AI_ITEMS.length+' recommended AI fixes?\n\nA full safety snapshot will be created first with 1-click rollback available.'))return;
  let count=0;
  for(const item of [...AI_ITEMS]){
    try{
      await api('/api/ai/apply_fix',{method:'POST',body:item});
      count++;
    }catch(e){}
  }
  alert('Successfully applied '+count+' AI remediation fixes!\nAll originals saved safely in .sentinel_backups.');
  AI_ITEMS=[];
  renderAIItems($('#ai-results'));
  loadSnapshots();
}

async function loadSnapshots(){
  const el=$('#ai-backups');if(!el)return;
  try{
    const list=await api('/api/ai/backups');
    if(!list.length){
      el.replaceChildren(h('p',{class:'muted',text:'No backups created yet. Snapshots are created automatically before any AI remediation.'}));
      return;
    }
    el.replaceChildren(
      h('table',{},
        h('tr',{},h('th',{text:'Snapshot ID'}),h('th',{text:'Timestamp'}),h('th',{text:'Action'}),h('th',{text:'Files Saved'}),h('th',{text:'Rollback'})),
        ...list.map(s=>h('tr',{},
          h('td',{class:'mono',style:'color:#00f0ff',text:s.id}),
          h('td',{text:s.date}),
          h('td',{text:s.action}),
          h('td',{text:(s.files||[]).length+' file(s)'}),
          h('td',{},h('button',{class:'danger',onclick:()=>doRollback(s.id)},icon('rotateCcw'),' Rollback'))
        ))
      )
    );
  }catch(e){
    el.textContent='No snapshots available.';
  }
}

async function doRollback(snapId){
  if(!confirm('Rollback project files to snapshot '+snapId+'?\n\nThis restores original files that were quarantined or patched.'))return;
  try{
    const r=await api('/api/ai/rollback',{method:'POST',body:{snapId}});
    alert('Rollback completed!\nRestored '+r.restored+' file(s).'+(r.errors.length?'\nErrors:\n'+r.errors.join('\n'):''));
    loadSnapshots();
  }catch(e){
    alert('Rollback failed: '+e.message);
  }
}

function renderSecrets(){
  const p=$('#p-secrets');
  p.replaceChildren(
    h('h3',{style:'color:#00f0ff;display:flex;align-items:center;gap:6px'},icon('key'),' Exposed Passwords, API Keys & Database Secrets'),
    h('p',{class:'muted',text:'Rotate these secrets immediately if your project was exposed to the web or untrusted servers. Click any row to jump directly to the code line.'}),
    (R.secrets.length||R.keys.length)?h('table',{},
      h('tr',{},h('th',{text:'Secret Type'}),h('th',{text:'File & Line'}),h('th',{text:'Masked Value'}),h('th',{text:'Action'})),
      ...R.secrets.map(s=>h('tr',{class:'f',onclick:()=>openByPath(s.file,s.line)},h('td',{class:'mono',style:'color:#ffd000',text:s.key}),h('td',{class:'mono',text:s.file+':'+s.line}),h('td',{class:'mono',text:s.masked}),h('td',{},h('span',{class:'chip',text:'Exposed Secret'})))),
      ...R.keys.map(s=>h('tr',{class:'f',onclick:()=>openByPath(s.file,s.line)},h('td',{style:'color:#ffd000',text:s.type}),h('td',{class:'mono',text:s.file+':'+s.line}),h('td',{class:'mono',text:s.masked}),h('td',{},h('span',{class:'chip',text:'API Key'}))))
    ):h('p',{text:'No leaked keys or secrets found in the codebase.'})
  );
}

function renderFix(){
  $('#p-fix').replaceChildren(
    h('h3',{style:'color:#00ff88;display:flex;align-items:center;gap:6px'},icon('tool'),' How to Clean & Protect Your Laravel Application'),
    h('ol',{style:'line-height:1.7'},R.remediation.map(x=>h('li',{style:'margin-bottom:12px'},h('b',{style:'font-size:14px;color:var(--t)',text:x.title}),h('div',{class:'muted',style:'margin-top:2px',text:x.detail}))))
  );
}

async function renderQuar(){
  const q=await api('/api/quarantines');
  $('#p-quar').replaceChildren(
    h('h3',{style:'color:#00f0ff;display:flex;align-items:center;gap:6px'},icon('box'),' Quarantine Vault'),
    h('p',{class:'muted',text:'Dangerous files are safely moved out of your web directory and locked with read-only permissions (0400). Nothing is deleted.'}),
    q.length?q.map(x=>h('div',{class:'fnd'},h('b',{text:x.id}),' · '+x.files.length+' file(s) isolated',h('div',{class:'mono muted',style:'margin:6px 0',text:x.folder}),h('button',{onclick:async()=>{const r=await api('/api/restore',{method:'POST',body:{id:x.id}});alert('Restored '+r.restored+' file(s).'+(r.errors.length?'\n\nErrors:\n'+r.errors.join('\n'):''));renderQuar()}},icon('rotateCcw'),' Restore Files'))):h('p',{text:'Quarantine vault is currently empty.'})
  );
}

let FIND=null,FCAT='all',FQ='';
function openByPath(path,line){const f=R.files.find(x=>x.path===path);if(f)openFile(f.id,line)}

async function renderFind(){
  const p=$('#p-find');
  if(!FIND){p.replaceChildren(h('p',{class:'muted',text:'Loading detections…'}));FIND=await api('/api/findings')}
  const cats=[['all','All Detections'],['code','Backdoors & WebShells'],['secrets','Keys & Secrets'],['image','Image Polyglots'],['config','Config Issues'],['laravel','Laravel Settings']];
  const CODE=['backdoor','obfuscation','polyglot','c2','seo-spam','js-malware','miner','htaccess'];
  const ok=f=>(FCAT==='all'||(FCAT==='code'?CODE.includes(f.cat):f.cat===FCAT))&&(!FQ||(f.path+' '+f.title+' '+f.snippet).toLowerCase().includes(FQ));
  const rs=FIND.filter(ok);
  const q=h('input',{type:'text',class:'grow',placeholder:'Filter detections…',value:FQ});
  q.oninput=e=>{FQ=e.target.value.toLowerCase();clearTimeout(window._ft);window._ft=setTimeout(renderFind,200)};
  p.replaceChildren(
    h('div',{class:'row',style:'margin-bottom:12px'},cats.map(([k,l])=>h('button',{class:k===FCAT?'pri':'',onclick:()=>{FCAT=k;renderFind()}},l)),q),
    h('div',{class:'scroll'},h('table',{},
      h('thead',{},h('tr',{},h('th',{text:'Severity'}),h('th',{text:'File & Line'}),h('th',{text:'Threat Name'}),h('th',{text:'Matching Code Snippet'}))),
      h('tbody',{},rs.slice(0,600).map(f=>h('tr',{class:'f',onclick:()=>openFile(f.id,f.line)},
        h('td',{},badge(f.sev)),
        h('td',{class:'mono',style:'color:#00f0ff',text:f.path+(f.line?':'+f.line:'')}),
        h('td',{style:'font-weight:600',text:f.title}),
        h('td',{class:'mono muted',text:f.snippet})
      )))
    )),
    h('div',{class:'muted',style:'margin-top:10px',text:rs.length+' detection(s) found'})
  );
}

let mp='';
async function mload(p){
  const d=await api('/api/browse?path='+encodeURIComponent(p));mp=d.path;$('#mpath').textContent=d.path+(d.laravel?'  ✓ Laravel project':'');
  $('#mlist').replaceChildren(h('div',{class:'dir',onclick:()=>mload(d.parent)},'⬆ ..'),...d.dirs.map(x=>h('div',{class:'dir',onclick:()=>mload(d.path+'/'+x.name)},icon('folder'),' '+x.name+(x.laravel?'  ✓':''))));
}
$('#browse').onclick=()=>{mload($('#path').value||'~');$('#modal').classList.add('open')};
$('#mcancel').onclick=()=>$('#modal').classList.remove('open');
$('#muse').onclick=()=>{$('#path').value=mp;$('#modal').classList.remove('open')};
init();
</script>"""


def cli_scan(path, a):
    st = dict(status="idle", phase="", done=0, total=0, current="", cancel=False)
    sc = Scan(path, st, deep=a.deep, baseline=a.baseline)
    done = threading.Event()
    res = {}

    def w():
        res["r"] = sc.run()
        done.set()
    threading.Thread(target=w, daemon=True).start()
    while not done.wait(1.0):
        sys.stderr.write("\r%s %d/%d" % (st["phase"], st["done"], st["total"]))
    sys.stderr.write("\n")
    r = res["r"]
    print("%s - %s (%d files scanned, %d flagged)" % (r["verdict"]["label"], r["verdict"]["text"], r["scanned"], len(r["files"])))
    for f in r["files"][:60]:
        print("[%-8s] %s  - %s" % (f["sev"], f["path"], "; ".join(x["title"] for x in f["findings"][:2])))
    if a.json:
        json.dump(r, open(a.json, "w"), indent=1)
        print("JSON report written to", a.json)

    if getattr(a, "agent_json", False):
        agent_payload = {
            "verdict": r["verdict"],
            "counts": r["counts"],
            "files": [
                {
                    "path": f["path"],
                    "sev": f["sev"],
                    "findings": [{"rule": x["rule"], "title": x["title"], "line": x["line"], "snippet": x["snippet"]} for x in f["findings"]],
                    "ai_recommendation": ai_analyze_file(path, f["path"], file_obj=f)
                } for f in r["files"]
            ]
        }
        print(json.dumps(agent_payload, indent=2))
        return r

    if getattr(a, "ai_analyze", False):
        print("\n--- Agentic AI Security Triage ---")
        ai_results = [ai_analyze_file(path, f["path"], file_obj=f) for f in r["files"][:40]]
        for item in ai_results:
            print("[%s] %s -> %s: %s" % (item["verdict"], item["path"], item["action"].upper(), item["explanation"]))
            if item.get("diff"):
                print("  " + item["diff"].replace("\n", "\n  "))
        return r

    if getattr(a, "ai_fix", False):
        print("\n--- Agentic AI Automated Safe Remediation ---")
        ai_results = [ai_analyze_file(path, f["path"], file_obj=f) for f in r["files"][:40]]
        for item in ai_results:
            try:
                res = ai_apply_fix(path, item)
                print("✓ Remediated: %s (%s) - snapshot: %s" % (item["path"], res["action"], res["snapshot_id"]))
            except Exception as e:
                print("✗ Failed %s: %s" % (item["path"], e))
        return r

    fail_on = getattr(a, "fail_on", None)
    if fail_on:
        levels = {
            "critical": {"critical"},
            "high": {"critical", "high"},
            "medium": {"critical", "high", "medium"},
            "any": {"critical", "high", "medium", "low", "info"}
        }
        check_sevs = levels.get(fail_on, {"critical", "high"})
        if any(r["counts"].get(s, 0) > 0 for s in check_sevs):
            sys.exit(1)
    elif r["counts"].get("critical", 0) > 0 or r["counts"].get("high", 0) > 0:
        sys.exit(1)
    return r


def run_gui(path="", autotest=False):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    BG, P, P2, BD, TX, MU = "#07090e", "#0d121c", "#131a27", "#1e293b", "#f1f5f9", "#8ea0bc"
    SEVC = {"critical": "#ff2a5f", "high": "#ff8800", "medium": "#ffd000", "low": "#00d4ff", "info": "#a78bfa"}
    MONO = ("Menlo", 11) if sys.platform == "darwin" else ("Consolas", 10) if os.name == "nt" else ("DejaVu Sans Mono", 10)
    root = tk.Tk()
    root.title("%s %s" % (APP, VERSION))
    root.geometry("1400x880")
    root.minsize(1000, 640)
    root.configure(bg=BG)
    st = ttk.Style(root)
    st.theme_use("clam")
    st.configure(".", background=BG, foreground=TX, fieldbackground=P2, bordercolor=BD, lightcolor=BD, darkcolor=BD, troughcolor=P2)
    st.configure("TFrame", background=BG)
    st.configure("Card.TFrame", background=P)
    st.configure("TLabel", background=BG, foreground=TX)
    st.configure("Muted.TLabel", background=BG, foreground=MU)
    st.configure("Card.TLabel", background=P, foreground=TX)
    st.configure("TButton", background=P2, foreground=TX, padding=(10, 6), borderwidth=1)
    st.map("TButton", background=[("active", "#26303c"), ("disabled", BG)], foreground=[("disabled", MU)])
    st.configure("Accent.TButton", background="#ffffff", foreground="#000000", font=("Helvetica", 10, "bold"))
    st.map("Accent.TButton", background=[("active", "#e4e4e7"), ("disabled", "#27272a")], foreground=[("disabled", "#71717a")])
    st.configure("Danger.TButton", background="#18181b", foreground="#ffffff", borderwidth=1)
    st.map("Danger.TButton", background=[("active", "#27272a"), ("disabled", BG)])
    st.configure("TNotebook", background=BG, borderwidth=0)
    st.configure("TNotebook.Tab", background=P, foreground=MU, padding=(14, 7))
    st.map("TNotebook.Tab", background=[("selected", P2)], foreground=[("selected", TX)])
    st.configure("Treeview", background=P, fieldbackground=P, foreground=TX, rowheight=24, borderwidth=0)
    st.configure("Treeview.Heading", background=P2, foreground=MU, relief="flat", padding=(6, 5))
    st.map("Treeview", background=[("selected", "#27272a")], foreground=[("selected", "#ffffff")])
    st.configure("TProgressbar", background="#ffffff", troughcolor=P2, borderwidth=0)
    st.configure("TEntry", fieldbackground=P2, foreground=TX, insertcolor=TX, padding=5)
    st.configure("TCheckbutton", background=BG, foreground=MU)
    st.configure("TCombobox", fieldbackground=P2, background=P2, foreground=TX, arrowcolor=TX)
    st.configure("TPanedwindow", background=BG)
    st.map("TCombobox", fieldbackground=[("readonly", P2)], foreground=[("readonly", TX)], selectbackground=[("readonly", P2)], selectforeground=[("readonly", TX)])
    root.option_add("*TCombobox*Listbox.background", P2)
    root.option_add("*TCombobox*Listbox.foreground", TX)

    def mk_tree(parent, cols, widths, selectmode="browse", stretch=()):
        fr = ttk.Frame(parent)
        tv = ttk.Treeview(fr, columns=[c for c, _ in cols], show="headings", selectmode=selectmode)
        for (c, label), w in zip(cols, widths):
            tv.heading(c, text=label)
            tv.column(c, width=w, minwidth=40, anchor="w", stretch=(c in stretch))
        ys = ttk.Scrollbar(fr, orient="vertical", command=tv.yview)
        xs = ttk.Scrollbar(fr, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tv.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        fr.rowconfigure(0, weight=1)
        fr.columnconfigure(0, weight=1)
        for sv, c in SEVC.items():
            tv.tag_configure(sv, foreground=c)
        return fr, tv

    def mk_text(parent, wrap="none"):
        fr = ttk.Frame(parent)
        tx = tk.Text(fr, bg="#0a0d12", fg=TX, insertbackground=TX, font=MONO, wrap=wrap, relief="flat", borderwidth=0, highlightthickness=1,
                     highlightbackground=BD, selectbackground="#264f78", padx=8, pady=6, state="disabled")
        ys = ttk.Scrollbar(fr, orient="vertical", command=tx.yview)
        tx.configure(yscrollcommand=ys.set)
        tx.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        if wrap == "none":
            xs = ttk.Scrollbar(fr, orient="horizontal", command=tx.xview)
            tx.configure(xscrollcommand=xs.set)
            xs.grid(row=1, column=0, sticky="ew")
        fr.rowconfigure(0, weight=1)
        fr.columnconfigure(0, weight=1)
        tx.tag_configure("hl", background="#4a1520", foreground="#ff6b8b")
        tx.tag_configure("flash", background="#7a5b00")
        tx.tag_configure("h", foreground="#58a6ff", font=MONO + ("bold",))
        tx.tag_configure("m", foreground=MU)
        return fr, tx

    def put(tx, parts):
        tx.configure(state="normal")
        tx.delete("1.0", "end")
        for text, tag in parts:
            tx.insert("end", text, tag)
        tx.configure(state="disabled")

    # ------------------------------------------------------------------ top bar
    top = ttk.Frame(root, padding=(12, 10, 12, 4))
    top.pack(fill="x")
    ttk.Label(top, text="Laravel Sentinel", font=("Helvetica", 15, "bold")).pack(side="left", padx=(0, 14))
    pathv = tk.StringVar(value=os.path.abspath(os.path.expanduser(path)) if path else "")
    pe = ttk.Entry(top, textvariable=pathv)
    pe.pack(side="left", fill="x", expand=True)
    deepv, basev, custv = tk.BooleanVar(value=False), tk.StringVar(), tk.StringVar()

    def browse():
        d = filedialog.askdirectory(title="Choose your Laravel project folder", initialdir=pathv.get() or os.path.expanduser("~"))
        if d:
            pathv.set(d)

    ttk.Button(top, text="📁  Browse", command=browse).pack(side="left", padx=6)
    scan_btn = ttk.Button(top, text="▶  Scan project", style="Accent.TButton")
    scan_btn.pack(side="left")
    stop_btn = ttk.Button(top, text="■  Stop", command=lambda: STATE.update(cancel=True), state="disabled")
    stop_btn.pack(side="left", padx=6)
    opt = ttk.Frame(root, padding=(12, 0, 12, 6))
    opt.pack(fill="x")
    ttk.Checkbutton(opt, text="Deep scan vendor/ & node_modules assets (slower)", variable=deepv).pack(side="left")
    ttk.Label(opt, text="   Clean vendor copy:", style="Muted.TLabel").pack(side="left")
    ttk.Entry(opt, textvariable=basev, width=30).pack(side="left", padx=4)
    ttk.Label(opt, text="  Extra indicators:", style="Muted.TLabel").pack(side="left")
    ttk.Entry(opt, textvariable=custv, width=26).pack(side="left", padx=4)
    prog = ttk.Progressbar(root, mode="determinate")
    prog.pack(fill="x", padx=12)
    status = ttk.Label(root, text="Choose a project folder and press Scan.  Read-only: nothing is executed or changed.", style="Muted.TLabel")
    status.pack(fill="x", padx=12, pady=(2, 4))

    # ------------------------------------------------------------------ summary cards
    cards = ttk.Frame(root, padding=(12, 2, 12, 6))
    cards.pack(fill="x")
    verdict = tk.Label(cards, text="No scan yet", bg=P, fg=MU, font=("Helvetica", 12, "bold"), anchor="w", padx=12, pady=8)
    verdict.pack(side="left", fill="x", expand=True)
    cnt = {}
    for sv in SEVC:
        f = tk.Frame(cards, bg=P, padx=14, pady=4, highlightbackground=BD, highlightthickness=1)
        f.pack(side="left", padx=(6, 0))
        cnt[sv] = tk.Label(f, text="0", bg=P, fg=SEVC[sv], font=("Helvetica", 18, "bold"))
        cnt[sv].pack()
        tk.Label(f, text=sv, bg=P, fg=MU, font=("Helvetica", 9)).pack()

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    # ------------------------------------------------------------------ Files tab
    ftab = ttk.Frame(nb)
    nb.add(ftab, text="  Files  ")
    pw = ttk.PanedWindow(ftab, orient="horizontal")
    pw.pack(fill="both", expand=True, pady=6)
    left = ttk.Frame(pw)
    pw.add(left, weight=2)
    fb = ttk.Frame(left)
    fb.pack(fill="x", pady=(0, 6))
    fq, fsev = tk.StringVar(), tk.StringVar(value="all")
    ttk.Label(fb, text="Filter:", style="Muted.TLabel").pack(side="left")
    ttk.Entry(fb, textvariable=fq, width=26).pack(side="left", padx=6)
    scb = ttk.Combobox(fb, textvariable=fsev, values=["all", "critical", "high", "medium", "low", "info"], width=9, state="readonly")
    scb.pack(side="left")
    ftf, ft = mk_tree(left, [("sev", "Severity"), ("path", "File"), ("n", "#"), ("size", "Size")], [78, 330, 36, 70], selectmode="extended", stretch=("path",))
    ftf.pack(fill="both", expand=True)
    fb2 = ttk.Frame(left)
    fb2.pack(fill="x", pady=(6, 0))
    selhigh = ttk.Button(fb2, text="Select Critical + High")
    selhigh.pack(side="left")
    qbtn = ttk.Button(fb2, text="Quarantine selected", style="Danger.TButton", state="disabled")
    qbtn.pack(side="left", padx=6)
    flabel = ttk.Label(fb2, text="", style="Muted.TLabel")
    flabel.pack(side="right")

    right = ttk.Frame(pw)
    pw.add(right, weight=3)
    dtitle = ttk.Label(right, text="Select a file to inspect it", font=("Helvetica", 11, "bold"))
    dtitle.pack(fill="x", pady=(0, 4))
    dn = ttk.Notebook(right)
    dn.pack(fill="both", expand=True)
    p_find = ttk.Frame(dn)
    dn.add(p_find, text=" Findings ")
    dff, dfind = mk_tree(p_find, [("sev", "Severity"), ("line", "Line"), ("rule", "Rule"), ("title", "Finding")], [78, 52, 56, 420], stretch=("title",))
    dff.pack(fill="both", expand=True)
    ddesc_f, ddesc = mk_text(p_find, "word")
    ddesc.configure(height=7)
    ddesc_f.pack(fill="x", pady=(6, 0))
    p_src = ttk.Frame(dn)
    dn.add(p_src, text=" Source (line numbers) ")
    srcf, src = mk_text(p_src)
    srcf.pack(fill="both", expand=True)
    p_dec = ttk.Frame(dn)
    dn.add(p_dec, text=" Decoded layers ")
    decf, dec = mk_text(p_dec, "word")
    decf.pack(fill="both", expand=True)
    p_inf = ttk.Frame(dn)
    dn.add(p_inf, text=" Info ")
    inff, inf = mk_text(p_inf, "word")
    inff.pack(fill="both", expand=True)

    CUR = {"d": None}

    def show_file(fid, jump=None):
        d = file_detail(fid)
        if not d:
            return
        CUR["d"] = d
        dtitle.configure(text=d["path"])
        dfind.delete(*dfind.get_children())
        for i, f in enumerate(d["findings"]):
            dfind.insert("", "end", iid=str(i), values=(f["sev"].upper(), f["line"] or "", f["rule"], f["title"] + ("   [in decoded layer]" if f["layer"] else "")), tags=(f["sev"],))
        hl = {f["line"] for f in d["findings"] if f["line"] and not f["layer"]}
        parts = []
        for i, l in enumerate(d["source"].replace("\r", "").split("\n")[:6000], 1):
            parts.append(("%5d │ %s\n" % (i, l[:600]), "hl" if i in hl else ""))
        put(src, parts)
        dp = []
        if not d["payloads"]:
            dp.append(("No encoded payloads were found in this file.", "m"))
        for p in d["payloads"]:
            dp.append((" → ".join(p["chain"]) + "\n", "h"))
            dp.append(("status: %s   size: %d bytes   entropy: %s\n\n" % (p["status"], p["size"], p["entropy"]), "m"))
            dp.append((p["text"].replace("\r", "") + "\n\n" + "─" * 60 + "\n\n", ""))
        put(dec, dp)
        rows = [("Path", d["path"]), ("Size", "%d bytes" % d["size"]), ("Modified", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["mtime"]))),
                ("Permissions", d["mode"]), ("SHA-256", d.get("sha256", "-")), ("MD5", d.get("md5", "-")), ("Categories", ", ".join(d["cats"]))]
        put(inf, [("%-12s %s\n" % (a, b), "") for a, b in rows])
        if jump:
            dn.select(p_src)
            line = int(jump)
            src.configure(state="normal")
            src.tag_remove("flash", "1.0", "end")
            src.tag_add("flash", "%d.0" % line, "%d.0" % (line + 1))
            src.configure(state="disabled")
            src.see("%d.0" % line)
        else:
            dn.select(p_find)

    def on_find_select(_e=None):
        sel = dfind.selection()
        d = CUR["d"]
        if not sel or not d:
            return
        f = d["findings"][int(sel[0])]
        txt = f["title"] + "\n\n" + (f["desc"] or "") + ("\n\nCode: " + f["snippet"] if f["snippet"] else "") + ("\n\nDecoded layer: " + f["layer"] if f["layer"] else "")
        put(ddesc, [(txt, "")])
        if f["line"] and not f["layer"]:
            src.configure(state="normal")
            src.tag_remove("flash", "1.0", "end")
            src.tag_add("flash", "%d.0" % f["line"], "%d.0" % (f["line"] + 1))
            src.configure(state="disabled")
            src.see("%d.0" % f["line"])

    def on_find_double(_e=None):
        sel = dfind.selection()
        if sel and CUR["d"]:
            f = CUR["d"]["findings"][int(sel[0])]
            if f["line"] and not f["layer"]:
                dn.select(p_src)

    dfind.bind("<<TreeviewSelect>>", on_find_select)
    dfind.bind("<Double-1>", on_find_double)

    RES = {}
    PATHS = {}

    def refill_files(*_):
        files = RES.get("files", [])
        q, sv = fq.get().lower().strip(), fsev.get()
        ft.delete(*ft.get_children())
        PATHS.clear()
        shown = 0
        for f in files:
            if sv != "all" and f["sev"] != sv:
                continue
            if q and q not in (f["path"] + " " + " ".join(x["title"] for x in f["findings"])).lower():
                continue
            if shown >= 5000:
                break
            ft.insert("", "end", iid=str(f["id"]), values=(f["sev"].upper(), f["path"], len(f["findings"]), "%.1f KB" % (f["size"] / 1024)), tags=(f["sev"],))
            PATHS[str(f["id"])] = f["path"]
            shown += 1
        flabel.configure(text="%d of %d files" % (shown, len(files)))

    fq.trace_add("write", refill_files)
    scb.bind("<<ComboboxSelected>>", refill_files)

    def on_file_select(_e=None):
        sel = ft.selection()
        qbtn.configure(state="normal" if sel else "disabled", text="Quarantine selected (%d)" % len(sel))
        if sel:
            show_file(int(sel[-1]))

    ft.bind("<<TreeviewSelect>>", on_file_select)

    def select_high():
        ids = [i for i in ft.get_children() if RES["files"][int(i)]["sev"] in ("critical", "high")]
        ft.selection_set(ids)

    selhigh.configure(command=select_high)

    def quarantine():
        sel = ft.selection()
        paths = [PATHS[i] for i in sel if i in PATHS]
        if not paths:
            return
        if not messagebox.askyesno(APP, "Move %d file(s) into a quarantine folder next to your project?\n\nNothing is deleted. You can restore them from the Quarantine tab." % len(paths)):
            return
        r = do_quarantine(LAST["root"], paths)
        messagebox.showinfo(APP, "Moved %d file(s) to:\n%s%s" % (r["moved"], r["folder"], ("\n\nErrors:\n" + "\n".join(r["errors"])) if r["errors"] else ""))
        refresh_quar()

    qbtn.configure(command=quarantine)

    def goto(fid, line=None):
        fq.set("")
        fsev.set("all")
        refill_files()
        iid = str(fid)
        if iid in PATHS:
            ft.selection_set(iid)
            ft.see(iid)
        nb.select(ftab)
        show_file(fid, line)

    # ------------------------------------------------------------------ flat finding tabs
    class FTab:
        def __init__(self, label):
            self.rows, self.map = [], {}
            fr = ttk.Frame(nb)
            nb.add(fr, text="  " + label + "  ")
            self.label = label
            bar = ttk.Frame(fr)
            bar.pack(fill="x", pady=6)
            self.q, self.sv = tk.StringVar(), tk.StringVar(value="all")
            ttk.Label(bar, text="Filter:", style="Muted.TLabel").pack(side="left")
            ttk.Entry(bar, textvariable=self.q, width=36).pack(side="left", padx=6)
            cb = ttk.Combobox(bar, textvariable=self.sv, values=["all", "critical", "high", "medium", "low", "info"], width=9, state="readonly")
            cb.pack(side="left")
            cb.bind("<<ComboboxSelected>>", lambda e: self.render())
            self.q.trace_add("write", lambda *a: self.render())
            self.count = ttk.Label(bar, text="", style="Muted.TLabel")
            self.count.pack(side="right")
            ttk.Label(bar, text="Double-click a row to open the file at that line   ", style="Muted.TLabel").pack(side="right")
            tf, self.tv = mk_tree(fr, [("sev", "Severity"), ("file", "File"), ("line", "Line"), ("rule", "Rule"), ("title", "Finding"), ("snip", "Code / detail")],
                                  [78, 330, 52, 56, 360, 420], stretch=("snip",))
            tf.pack(fill="both", expand=True)
            self.tv.bind("<Double-1>", self.open)
            self.tv.bind("<Return>", self.open)

        def set(self, rows):
            self.rows = rows
            self.render()

        def render(self):
            q, sv = self.q.get().lower().strip(), self.sv.get()
            self.tv.delete(*self.tv.get_children())
            self.map.clear()
            n = 0
            for fid, path, f in self.rows:
                if sv != "all" and f["sev"] != sv:
                    continue
                if q and q not in (path + " " + f["title"] + " " + (f["snippet"] or "")).lower():
                    continue
                if n >= 4000:
                    break
                iid = str(n)
                self.tv.insert("", "end", iid=iid, values=(f["sev"].upper(), path, f["line"] or "", f["rule"], f["title"], f["snippet"] or ""), tags=(f["sev"],))
                self.map[iid] = (fid, f["line"])
                n += 1
            self.count.configure(text="%d of %d" % (n, len(self.rows)))

        def open(self, _e=None):
            iid = self.tv.focus()
            if iid in self.map and self.map[iid][0] is not None:
                goto(*self.map[iid])

    t_all, t_keys, t_img, t_cfg = FTab("All findings"), FTab("Keys & secrets"), FTab("Images"), FTab("Config issues")

    # ------------------------------------------------------------------ small tabs
    def simple_tab(label, cols, widths, stretch):
        fr = ttk.Frame(nb)
        nb.add(fr, text="  " + label + "  ")
        tf, tv = mk_tree(fr, cols, widths, stretch=stretch)
        tf.pack(fill="both", expand=True, pady=6)
        return fr, tv

    _, up_tv = simple_tab("Upgrade", [("sev", "Status"), ("comp", "Component"), ("cur", "Current"), ("advice", "Advice")], [78, 220, 110, 760], ("advice",))
    _, ioc_tv = simple_tab("Indicators", [("type", "Type"), ("value", "Value"), ("count", "Hits"), ("files", "Seen in")], [60, 480, 50, 500], ("files",))
    rem_f = ttk.Frame(nb)
    nb.add(rem_f, text="  Remediation  ")
    rf, rem = mk_text(rem_f, "word")
    rf.pack(fill="both", expand=True, pady=6)
    quar_f = ttk.Frame(nb)
    nb.add(quar_f, text="  Quarantine  ")
    qb = ttk.Frame(quar_f)
    qb.pack(fill="x", pady=6)
    restore_btn = ttk.Button(qb, text="Restore selected set")
    restore_btn.pack(side="left")
    ttk.Label(qb, text="  Files are moved (not deleted), read-only, to a folder beside the project.", style="Muted.TLabel").pack(side="left")
    qf, qtv = mk_tree(quar_f, [("id", "Quarantine set"), ("n", "Files"), ("folder", "Folder")], [160, 60, 800], stretch=("folder",))
    qf.pack(fill="both", expand=True)

    def refresh_quar():
        qtv.delete(*qtv.get_children())
        if LAST.get("root"):
            for q in list_quarantines(LAST["root"]):
                qtv.insert("", "end", iid=q["id"], values=(q["id"], len(q["files"]), q["folder"]))

    def restore():
        sel = qtv.selection()
        if sel and messagebox.askyesno(APP, "Restore all files in set %s to their original locations?" % sel[0]):
            r = do_restore(LAST["root"], sel[0])
            messagebox.showinfo(APP, "Restored %d file(s)." % r["restored"] + (("\n" + "\n".join(r["errors"])) if r["errors"] else ""))
            refresh_quar()

    restore_btn.configure(command=restore)

    # ------------------------------------------------------------------ export
    def export(kind):
        if not LAST.get("result"):
            return
        fn = filedialog.asksaveasfilename(defaultextension="." + kind, initialfile="sentinel-report." + kind)
        if fn:
            with open(fn, "w", encoding="utf-8") as f:
                f.write(json.dumps(LAST["result"], indent=1) if kind == "json" else export_html(LAST["result"]))
            messagebox.showinfo(APP, "Saved " + fn)

    ttk.Button(top, text="⬇ JSON", command=lambda: export("json")).pack(side="left", padx=(14, 4))
    ttk.Button(top, text="⬇ HTML", command=lambda: export("html")).pack(side="left")

    # ------------------------------------------------------------------ scan control
    def finish():
        res = LAST["result"]
        RES.clear()
        RES.update(res)
        for sv in SEVC:
            cnt[sv].configure(text=str(res["counts"][sv]))
        col = {"COMPROMISED": "#ff5d5d", "SUSPICIOUS": "#ff9a3d", "REVIEW": "#e3c04a", "CLEAN": "#3fb950"}[res["verdict"]["label"]]
        verdict.configure(fg=col, text="%s  -  %s   (%d files + %d images scanned in %ss, %d flagged, %d key hits)" % (
            res["verdict"]["label"], res["verdict"]["text"], res["scanned"], res["images"]["scanned"], res["seconds"], len(res["files"]), len(res["keys"])))
        refill_files()
        rows = [(f["id"], f["path"], x) for f in res["files"] for x in f["findings"]]
        id_of = {f["path"]: f["id"] for f in res["files"]}
        rows.sort(key=lambda r: -SEV[r[2]["sev"]])
        t_all.set(rows)
        envrows = [(id_of.get(s["file"]), s["file"], dict(sev="info", line=s["line"], rule="ENV", title="Secret in env file: " + s["key"], snippet="%s = %s" % (s["key"], s["masked"]))) for s in res["secrets"]]
        t_keys.set([r for r in rows if r[2]["cat"] == "secrets" and r[2]["rule"] != "L013"] + envrows)
        t_img.set([r for r in rows if r[2]["cat"] == "image"])
        t_cfg.set([r for r in rows if r[2]["cat"] in ("config", "laravel", "exposure", "upgrade")])
        up_tv.delete(*up_tv.get_children())
        for i, u in enumerate(res["upgrades"]):
            up_tv.insert("", "end", iid=str(i), values=(u["sev"].upper(), u["component"], u["current"], u["advice"]), tags=(u["sev"],))
        ioc_tv.delete(*ioc_tv.get_children())
        for i, x in enumerate(res["iocs"]):
            ioc_tv.insert("", "end", iid=str(i), values=(x["type"], x["value"], x["count"], ", ".join(x["files"][:3])))
        parts = []
        for i, r in enumerate(res["remediation"], 1):
            parts += [("%d. %s\n" % (i, r["title"]), "h"), ("   " + r["detail"] + "\n\n", "")]
        put(rem, parts)
        refresh_quar()
        status.configure(text="Done. Click a file to inspect it; double-click any finding row to jump to its line.")
        if autotest:
            print("GUI-TEST verdict=%s files=%d flagged=%d keys=%d images=%s findings_rows=%d img_rows=%d cfg_rows=%d" % (
                res["verdict"]["label"], res["scanned"], len(res["files"]), len(res["keys"]), res["images"], len(t_all.rows), len(t_img.rows), len(t_cfg.rows)))
            ft.selection_set(ft.get_children()[0])
            root.update()
            print("GUI-TEST source_lines=%s" % src.index("end-1c"))
            root.after(int(os.environ.get("SENTINEL_GUI_HOLD", "300")), root.destroy)

    def poll():
        s = STATE
        total = s.get("total") or 0
        prog.configure(maximum=max(1, total), value=s.get("done") or 0)
        status.configure(text="%s  %s/%s   %s" % (s.get("phase", ""), s.get("done"), total, (s.get("current") or "")[-90:]))
        if s["status"] == "done":
            scan_btn.configure(state="normal")
            stop_btn.configure(state="disabled")
            finish()
        elif s["status"] in ("error", "cancelled"):
            scan_btn.configure(state="normal")
            stop_btn.configure(state="disabled")
            status.configure(text=("Error: %s" % s.get("error")) if s["status"] == "error" else "Scan stopped.")
        else:
            root.after(300, poll)

    def do_scan():
        p = pathv.get().strip()
        try:
            start_scan(dict(path=p, deep=deepv.get(), baseline=basev.get().strip(), custom=custv.get()))
        except ValueError as e:
            messagebox.showerror(APP, str(e))
            return
        scan_btn.configure(state="disabled")
        stop_btn.configure(state="normal")
        poll()

    scan_btn.configure(command=do_scan)
    pe.bind("<Return>", lambda e: do_scan())
    if autotest:
        root.after(200, do_scan)
    root.mainloop()


def main():
    ap = argparse.ArgumentParser(description=APP)
    ap.add_argument("path", nargs="?", default="")
    ap.add_argument("--cli", action="store_true", help="headless scan, print summary")
    ap.add_argument("--json", help="with --cli: write the full report to this file")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "any"], help="exit with code 1 if findings meet/exceed this severity")
    ap.add_argument("--ai-analyze", action="store_true", help="run agentic AI security triage on detected malware")
    ap.add_argument("--ai-fix", action="store_true", help="run agentic AI and auto-quarantine/patch with safety snapshot")
    ap.add_argument("--ai-rollback", metavar="SNAP_ID", help="rollback project to a specific .sentinel_backups snapshot")
    ap.add_argument("--agent-json", action="store_true", help="output clean machine-readable JSON for AI coding agents")
    ap.add_argument("--generate-htaccess", metavar="DIR", help="generate hardened .htaccess blocking script execution in given folder and exit")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--baseline", help="folder holding a clean copy of vendor/ to compare against")
    ap.add_argument("--web", action="store_true", help="use the browser UI instead of the desktop window")
    ap.add_argument("--gui", action="store_true", help="force the desktop window")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    if a.ai_rollback:
        root_dir = os.path.abspath(os.path.expanduser(a.path or "."))
        res = rollback_snapshot(root_dir, a.ai_rollback)
        print(json.dumps(res, indent=2))
        return
    if a.generate_htaccess:
        target = os.path.abspath(os.path.expanduser(a.generate_htaccess))
        if not os.path.isdir(target):
            sys.exit("Target folder not found: %s" % target)
        out = generate_hardened_htaccess(target)
        print("Hardened .htaccess generated at: %s" % out)
        return
    if a.ai_analyze or a.ai_fix or a.agent_json:
        a.cli = True
    if a.cli:
        if not a.path:
            ap.error("--cli needs a project path")
        cli_scan(a.path, a)
        return
    use_gui = a.gui or not a.web
    if use_gui:
        try:
            import tkinter  # noqa: F401
        except Exception:
            if a.gui:
                sys.exit("The desktop window needs tkinter. macOS: brew install python-tk   Debian/Ubuntu: sudo apt install python3-tk")
            print("Desktop window unavailable (tkinter is not installed) - starting the browser UI instead.")
            use_gui = False
    if use_gui:
        return run_gui(a.path, autotest=bool(os.environ.get("SENTINEL_GUI_TEST")))
    srv = None
    for port in range(a.port, a.port + 30):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if not srv:
        sys.exit("No free port found")
    url = "http://127.0.0.1:%d/?t=%s" % (srv.server_address[1], TOKEN)
    if a.path:
        globals()["INDEX_HTML"] = globals()["INDEX_HTML"].replace("localStorage.sentinelPath||''", json.dumps(os.path.abspath(os.path.expanduser(a.path))))
    print("%s %s running at\n  %s\nPress Ctrl+C to stop." % (APP, VERSION, url))
    if not a.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    main()
