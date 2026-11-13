# Laravel Sentinel

> **Powered by Kneazle**  
> **Local malware scanner, multi-layer deobfuscator, and security triage engine tailored specifically for Laravel applications.**

Zero external dependencies • Standard library only (Python 3.8+) • Safe & strictly read-only scanning

---

## Key Highlights

* **100% Safe & Read-Only**: Sentinel never executes, includes, or `eval()`s untrusted code. Obfuscated payloads are extracted using deterministic data transformations (base64, raw inflate, bzip2, rot13, XOR, steganography).
* **Laravel-Specific Intelligence**:
  * Knows valid compiled Blade views (`storage/framework/views/[hash].php`) while flagging anomalous PHP scripts in `storage/`, `public/uploads/`, `.git/`, and asset folders.
  * Audits web root exposure (e.g. rewrite rules exposing `.env`, `vendor/`, or `.git/`).
  * Audits `storage/app/public` for missing script-execution blocks.
  * Audits Task Scheduler persistence (`Schedule::exec`, closures running `eval/system`).
  * Audits dangerous upload logic (`getClientOriginalExtension()`, moving directly to `public/`).
  * Audits security misconfigurations (`APP_DEBUG=true`, missing `APP_KEY`, insecure session cookies, permissive CORS, CSRF exceptions).
* **Advanced Multi-Layer Deobfuscator**: Recursively unwraps up to 30 layers of nested compression, encoding, XOR brute-forcing, string concatenation folding (`'a'.'b'`), `chr()` chains, whitespace steganography, and zero-width unicode hiding.
* **Polyglot & Image Header Inspection**: Inspects JPEG segments (`APP*`, `COM` comments) and PNG chunks (`tEXt`, `zTXt`, `iTXt`) for embedded PHP code or payloads appended after EOF markers (`FF D9`, `IEND`).
* **Secret & Credential Harvesting**: Finds exposed API keys (AWS, Google, Stripe, Slack, GitHub, SendGrid, private keys, JWTs) and masks values for privacy.
* **Non-Destructive Quarantine**: Safely isolates flagged files into `<project>_QUARANTINE/<timestamp>` with read-only permissions (`0400`) and a JSON audit manifest, with one-click restore.
* **Three Operating Modes**:
  1. **Desktop GUI** (Tkinter) with dark theme and syntax highlighting.
  2. **Local Web UI** (Single-page app on `127.0.0.1` protected by a cryptographically random session token).
  3. **Headless CLI** with exit codes for CI/CD automation.

---

## Installation

Laravel Sentinel requires **Python 3.8 or higher** and has **no pip dependencies**.

```bash
git clone https://github.com/devwithanandhukannan/Laravel-Sentinel.git
cd Laravel-Sentinel
```

---

## Usage

### 1. Desktop GUI (Default)
Launch the standalone desktop interface:
```bash
python3 laravel_sentinel.py /path/to/laravel-project
```

### 2. Interactive Web UI
Prefer working in your browser? Pass `--web` to launch the local web server:
```bash
python3 laravel_sentinel.py /path/to/laravel-project --web
```
*Listens on `127.0.0.1` only with a per-run authorization token.*

### 3. Headless CLI (CI/CD Pipelines)
Run automated security scans in GitHub Actions, GitLab CI, or deployment scripts:
```bash
# Basic scan with JSON report output
python3 laravel_sentinel.py /path/to/laravel-project --cli --json report.json

# Fail build if Critical or High severity findings exist (exits with code 1)
python3 laravel_sentinel.py /path/to/laravel-project --cli --fail-on high

# Deep scan vendor and node_modules assets
python3 laravel_sentinel.py /path/to/laravel-project --cli --deep
```

### 4. Hardened `.htaccess` Generator
Generate an `.htaccess` file that explicitly disables PHP script execution in public upload or asset directories (e.g. `storage/app/public`):
```bash
python3 laravel_sentinel.py --generate-htaccess /path/to/storage/app/public
```

---

## Detection Coverage

| Category | Description |
| :--- | :--- |
| **Backdoors & Webshells** | Detects WSO, c99, r57, b374k, IndoXploit, TinyFileManager, China Chopper, Weevely, dynamic function calls, request-fed execution (`eval`, `assert`, `system`, `passthru`, `proc_open`). |
| **Callback Execution** | Flags callback-based evasion via `array_map`, `array_filter`, `usort`, `register_shutdown_function`, etc. |
| **Stream Wrappers** | Flags `php://filter` chain exploits, `zip://`, `phar://`, `data://` stream inclusion. |
| **SEO Cloaking & C2** | Detects search-engine user-agent switching (Googlebot/Baidu), crawler blocking lists, and malicious C2 domains. |
| **Polyglots** | Identifies scripts disguised as images or images with PHP injected into EXIF / comments or appended past end-of-image markers. |
| **Configuration Risks** | Insecure session cookies (`http_only = false`, unencrypted on HTTPS), debug mode active, missing CSRF tokens, loose CORS with credentials. |
| **Dependency Audits** | Flags dev tools installed in production (`debugbar`, `telescope`, `ignition`, `clockwork`, `horizon`, `pulse`). |

---

## License

Distributed under the [MIT License](LICENSE).
