# Repository Guidelines

## Project Structure & Module Organization
- Project-owned logic lives in `sshkey.c` with headers in `*.h`; use
  these as primary references.
- Imported sources include `cfx.c`, `cfx.h`, `curve25519-donna.c`,
  `sequence.c` and keep their upstream formatting.
- `sshkey.asn1` is the schema; generated outputs are `asn1_sshkey.c`,
  `sshkey.h`, `sshkey-priv.h`, plus `*.x`, `*.hx`, and `sshkey_files`
  (regenerate via `asn1_compile`, do not hand-edit).
- `main.c`, `verify.c`, `mkpem.c`: small utilities or experiments;
  binaries `main`, `verify`, `mkpem` are local artifacts.
- Sample fixtures and key material live at `msg`, `pkey`, `pkey2`,
  `sig*`, `ed25519.pem`, `public_key.pem`.

## Build, Test, and Development Commands
- `make`: builds `sshkey.so` from the sources in `SRCS`; requires
  `asn1_compile`, Heimdal headers, libssh2, and OpenSSL.
- `make clean`: removes `sshkey.so`.
- `make asn1_sshkey.x sshkey-priv.hx sshkey.hx sshkey_files`: regenerates
  ASN.1 outputs after editing `sshkey.asn1` (running `make` after touching
  `sshkey.asn1` also works).
- Utilities are not wired into the Makefile; compile them manually with
  the same include/lib paths as in `Makefile` if needed.

## Coding Style & Naming Conventions
- C files:
  - 80 columns
  - Indentation: follow `sshkey.c` and `sshkey.h` (tabs, K&R braces) for new or
    edited handwritten code.
  - Naming: `snake_case` for functions and locals, `UPPER_SNAKE_CASE` for macros,
    `CamelCase` for ASN.1-generated types.
- YAML files and MD files:
  - 80 columns
  - 2 space indents
  - line text up on lists
- No formatter or linter config exists
- Avoid reformatting generated or imported files.

## Testing Guidelines
- No automated test framework is present.
- If adding tests, place them in a new `tests/` directory and document the runner
  in `Makefile` (e.g., `tests/*_test.c`).

## Commit & Pull Request Guidelines
- Commit history is informal (e.g., short subjects like "quick
  checkpoint"); use concise, descriptive subjects and add context in the
  body when behavior changes.
- PRs should include a summary, build steps, dependency notes (e.g.,
  local include/lib paths), and mention any regenerated ASN.1 outputs.
- A commit should implement one distinct change
- Never mix whitespace and functional changes in a single commit
- Tests for a feature should be in the same commit that implements
  the feature
- DO NOT commit any generated files
- put all generated files into .gitignore

## Security & Configuration Tips
- Do not commit real private keys or credentials; keep `*.pem` as test-only
  material.
- Update `CFLAGS` and `LDFLAGS` in `Makefile` to match local install paths
  instead of hard-coding new ones in source.

## Documentation
- README.md should provide a high level description of the project
  along with reasons one might use it
- README.md should also describe how to build, install, configure, and use the code
- The protocol should be documented in sshkey.asn1 comments alongside
  the ASN.1 descriptions of the messages
- keep README.md up to date when build, install, use, configuration
  changes necessitate it
- keep sshkey.asn1 up to date on the design and protocol specification
