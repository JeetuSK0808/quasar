# Security & responsible use

Quasar is a **defensive** research tool. It **parses** files and reports what they
look like they would do; it never executes, unpacks-and-runs, modifies, or
transmits a sample. All analysis is static and local.

## Handling samples safely

Quasar reading a file is safe — it only parses bytes. **Possessing and moving the
underlying malware is not.** If you analyze live malware:

- Know and follow the laws of your jurisdiction on handling malicious code.
- Keep samples in an isolated location; never double-click or run them.
- Do not commit samples to this repository or any public repository. The
  `.gitignore` already blocks `samples/` and common executable types
  (`.exe`, `.dll`, `.sys`, `.bin`, `.dmp`, `.vir`), but the responsibility is yours.

Quasar must not be used to build, modify, weaponize, or distribute malware. It
exists to help defenders understand it.

## Reporting a vulnerability in Quasar

If you find a security issue in Quasar itself (for example, a parser that can be
made to crash, hang, or execute code on a crafted input), please report it
privately rather than opening a public issue:

- Open a private advisory via **GitHub → Security → Report a vulnerability**, or
- email **jeetusk08@gmail.com**.

Please include the input (or a minimal reproducer) and what you observed. I aim
to acknowledge reports within a few days. Because Quasar parses hostile input by
design, parser-hardening reports are especially welcome.
