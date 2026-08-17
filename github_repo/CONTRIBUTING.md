# Contributing to NetWARRIOR

Contributions are welcome. Before submitting anything, read this file.

---

## Ground Rules

1. **Authorized use only.** All contributions must be usable solely for legitimate,
   authorized security testing. Do not add features whose only purpose is unauthorized
   access or harm.

2. **No hardcoded targets.** Never commit IP addresses, domains, credentials, or
   captured data of any kind.

3. **No malware.** Do not contribute code that would qualify as malware under any
   reasonable definition — self-replicating code, silent persistence without user
   consent, etc.

4. **Defensive framing.** Every feature should be documentable in terms of what
   defenders need to understand to protect against it.

---

## How to Contribute

### Bug Reports

Open an issue with:
- Python version and OS
- Exact command or action that triggered the bug
- Full error output (stack trace if available)
- Expected vs actual behavior

### Feature Requests

Open an issue describing:
- What the feature does
- Why it is useful for authorized security testing
- Any known prior art (similar tools, CVEs it helps test, etc.)

### Pull Requests

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Verify: `python3 -c "import ast; ast.parse(open('netwarrior.py').read()); print('OK')`
5. Open a PR with a clear description of what changed and why

---

## Code Standards

- Async-first. Any I/O-bound operation goes through `asyncio`. Blocking calls
  (scapy, paramiko) go in `loop.run_in_executor(None, ...)`.
- `except Exception:` not bare `except:` — never swallow `KeyboardInterrupt`.
- Wordlists stream line by line. Never load the entire file into memory.
- All attack methods return `AttackState`. Consistent interface, no exceptions.
- No emojis in the UI. Color and text labels carry all visual hierarchy.
- Terminal size detected at render time, not at init.

---

## What Will Not Be Merged

- Features designed to evade detection by defenders (obfuscation layers, AV evasion)
- Exploit code for specific unpatched CVEs
- Automated lateral movement or worm-like propagation
- Anything that removes or weakens the legal disclaimer

---

## Credits

Add yourself to the contributors section of the README when your PR is merged.
