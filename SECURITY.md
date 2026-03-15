# Security Policy

## Maintainer

NIfra is built and maintained by **[ReyraLabs](https://reyralabs.com)** — Surabaya, Indonesia 🇮🇩.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |

## Responsible Disclosure

If you discover a security vulnerability in NIfra itself, please report it
responsibly — do NOT open a public GitHub issue.

**Report via:** GitHub Security Advisories (preferred)
→ Go to the repository → Security tab → "Report a vulnerability"

Or email: open a GitHub Security Advisory at https://github.com/reyracom/Nifra-Agent/security/advisories

We will acknowledge receipt within 48 hours and aim to release a fix
within 14 days for critical issues.

## Scope

**In scope:**
- Vulnerabilities in NIfra's core engine
- Attack cases that contain fully weaponized payloads (we will remove them)
- Dependency vulnerabilities with a clear exploit path

**Out of scope:**
- Vulnerabilities in the playground apps (they are intentionally vulnerable)
- Theoretical or speculative issues without an exploit path

## Authorized Use

NIfra is designed for **authorized security testing of your own AI systems**.

- Only use NIfra to test systems you own or have **explicit written authorization** to test
- Using the tool against systems without authorization may violate computer fraud laws
- The exploit payloads in the `attacks/` library are for research and education only

By using NIfra, you agree to use it only for lawful, authorized security testing.
