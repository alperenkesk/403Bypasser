<h1 align="center">403 Bypasser</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat" alt="License">
  <img src="https://img.shields.io/badge/Version-1.1-orange?style=flat" alt="Version">
</p>

<p align="center">
  <b>Advanced 403/401 Bypasser & Access Control Fuzzer</b>
</p>

![Screenshot](screenshot.png)

<p align="center">
  A specialized command-line tool for bypassing <code>403 Forbidden</code> and <code>401 Unauthorized</code> endpoints. Built on the <b>Cobra Framework</b>, it uses advanced header manipulation, path normalization, and HTTP method fuzzing techniques to test and evade Access Control Lists (ACLs).
</p>

---

## Key Features

- **Success-Oriented:** Automatically filters noise and displays only matching status codes (default: `200 OK`).
- **Smart Calibration:** Automatically measures 404 and root page sizes to eliminate false positives.
- **Embedded Wordlist:** Works out of the box — no wordlist file needed. The default wordlist is compiled into the binary.
- **Deep Scan Mode:** Exhaustive nested path × header fuzzing for high-security targets.
- **6 HTTP Methods:** Tests GET, POST, TRACE, HEAD, OPTIONS, and PUT for method-based bypass.
- **Custom Status Codes:** Report any status code you care about (e.g. `301`, `302`, `500`).
- **Configurable Timeout:** Set your own request timeout instead of a hardcoded value.
- **Auto Logging:** All hits are instantly saved to an output file.
- **Wordlist Deduplication:** Duplicate entries in the wordlist are automatically skipped.
- **Request Estimate:** Shows estimated request count before scan starts, with a warning for large deep scans.

---

## Installation

### Option 1: Go Install (Recommended)

```bash
go install -v github.com/alperenkesk/403Bypasser@latest
```

> Requires Go 1.20+. Ensure `$(go env GOPATH)/bin` is in your `$PATH`.

### Option 2: Build from Source

```bash
git clone https://github.com/alperenkesk/403Bypasser.git
cd 403Bypasser
make install
```

---

## Usage

```bash
# Basic scan (uses embedded default wordlist)
403bypasser -u "https://target.com"

# Custom wordlist
403bypasser -u "https://target.com" -w "my_wordlist.txt"

# Deep scan
403bypasser -u "https://target.com" -D

# Show 200, 301, and 302 responses
403bypasser -u "https://target.com" -s 200,301,302

# Custom timeout and delay
403bypasser -u "https://target.com" -T 15 -d 200
```

### Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--url` | `-u` | Target URL **(Required)** | — |
| `--wordlist` | `-w` | Path to wordlist file | embedded |
| `--cookie` | `-c` | Raw session cookie (e.g. `JSESSIONID=xxx`) | `""` |
| `--header` | `-H` | Custom header, repeatable (e.g. `-H 'X-Token: abc'`) | — |
| `--proxy` | `-p` | Proxy URL (e.g. `http://127.0.0.1:8080`) | — |
| `--output` | `-o` | Output file for results | `results.txt` |
| `--threads` | `-t` | Concurrent threads | `10` |
| `--timeout` | `-T` | HTTP request timeout in seconds | `10` |
| `--delay` | `-d` | Delay between requests in milliseconds | `0` |
| `--deep` | `-D` | Enable Deep Scan (path × header × method fuzzing) | `false` |
| `--show-codes` | `-s` | Status codes to report (comma-separated) | `200` |
| `--verbose` | `-v` | Show errors and failed requests | `false` |
| `--help` | `-h` | Show help | — |

---

## Examples

**1. Proxy Support (Burp Suite / Caido)**
```bash
403bypasser -u "https://target.com" -p "http://127.0.0.1:8080"
```

**2. Custom Headers & Authorization**
```bash
403bypasser -u "https://api.target.com" -H "Authorization: Bearer XYZ123" -H "X-Client-ID: 99"
```

**3. WAF / Rate Limit Evasion**
```bash
403bypasser -u "https://target.com" -t 5 -d 500
```

**4. Deep Scan**
```bash
403bypasser -u "https://target.com" -D
```

**5. Report Multiple Status Codes**
```bash
403bypasser -u "https://target.com" -s 200,301,302,500
```

**6. Custom Timeout for Slow Targets**
```bash
403bypasser -u "https://target.com" -T 30
```

---

## Bypass Techniques

| Category | Techniques |
|----------|-----------|
| **Path Manipulation** | Slash variations, dot segments, semicolon injection, URL encoding, double encoding |
| **HTTP Methods** | GET, POST, TRACE, HEAD, OPTIONS, PUT |
| **IP Spoofing Headers** | `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, and 10 more |
| **URL Override Headers** | `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-URL` |
| **Scheme Headers** | `X-Forwarded-Scheme: http/https` |
| **Referer Tricks** | `Referer: http://127.0.0.1`, `Referer: https://localhost` |
| **Misc** | `Range: bytes=0-`, `X-HTTP-Method-Override` |

---

## Contributing

Contributions are welcome!

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/NewPayloads`).
3. Commit your changes.
4. Push to the branch.
5. Open a Pull Request.

---

## Disclaimer

This tool is developed for **educational purposes** and **authorized security testing** only. The author is not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing any system.

---

<p align="center">
  Crafted for Security Researchers by <a href="https://github.com/alperenkesk">alperenkesk</a>
</p>
