---
name: readable-short-code
description: Write or simplify Python code in this DES project so it stays short, clear to a beginner, and functionally complete.
---

# Readable, short code

When editing this project, use the fewest straightforward steps that preserve the requested behavior.

- Prefer familiar Python statements, descriptive names, and simple loops over clever expressions or layers of helper functions.
- Remove duplicated logic and obsolete code. Keep comments that explain a DES or authentication step; avoid comments that merely repeat a line of code.
- Keep standard DES in `des.py` separate from added processes unless the task explicitly changes DES.
- Do not shorten away input checks, HMAC verification before decryption, random IV generation, padding validation, or meaningful tests.
- Preserve the user's existing explanatory comments when changing code they wrote, unless those comments have become inaccurate; explain any necessary change.
- After simplifying, run the relevant terminal flow and tests. Report what became shorter and what still works.
- When teaching or sending snippets, explain the code in plain language, line by line when requested.
