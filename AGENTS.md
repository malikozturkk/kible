# AGENTS.md

This repository's instructions for AI coding agents live in **[`CLAUDE.md`](CLAUDE.md)**.

**Read it before making any change.** It opens with a `Rules` section (R1–R9) that applies to every
task without being asked — read the relevant doc before writing code, update the docs in the same
change, leave the recorded known gaps alone, never touch secrets or send real email, never adjust
religious content unasked, and report honestly what was verified versus inferred. The rest of the
file covers the stack, module conventions, the response envelope, date/timezone invariants, and the
domain rules that are easy to get wrong.

Supporting documentation is in [`docs/`](docs/):

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module graph and request lifecycle
- [`docs/API.md`](docs/API.md) — endpoint reference
- [`docs/DOMAIN.md`](docs/DOMAIN.md) — prayer, quiz, XP and streak rules
- [`docs/DATA-MODEL.md`](docs/DATA-MODEL.md) — Prisma models
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — setup and troubleshooting
