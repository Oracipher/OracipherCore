# Contributing to OracipherCore

OracipherCore is an experimental C11 cryptographic library. Changes involving cryptographic formats, keys, file handling, PKI, or randomness require careful review and negative-path tests. **Passing unit tests does not establish that a cryptographic implementation is secure.**

## Before contributing

1. Look for an existing issue or open a scoped issue describing the defect or feature. Never disclose an exploitable, unpatched security vulnerability in a public issue; see [SECURITY.md](SECURITY.md).
2. Create a branch from `main`. Suggested names: `fix/<topic>`, `feat/<topic>`, `docs/<topic>`, or `chore/<topic>`. Do not create a permanent branch for every version.
3. Keep unrelated cleanups in separate pull requests. Explain changes to any cryptographic protocol, key format, or on-disk representation.
4. Do not commit passwords, keys, peppers, certificates with private keys, or production data. Use test-only fixtures and clearly mark them.

## Build and test on Linux

Prerequisites: CMake, a C11 compiler, `pkg-config`, libsodium, OpenSSL >= 3.0, and libcurl >= 8.4.0. See `CMakeLists.txt` for authoritative requirements.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

CTest registers the repository's tests with an explicit **test-only** `HSC_PEPPER_HEX`. Do not reuse that value for any real keys or data.

For native Windows builds, provide the dependencies and `pkg-config` integration expected by the current CMake configuration. Document the actual toolchain used; do not claim cross-platform validation from a Linux-only run.

## Pull request requirements

- Link the issue(s) being addressed and describe the smallest possible change.
- Provide exact commands and **real** results: compiler/version, platform, tests executed, CI run URL, and any skipped tests.
- For data-handling changes, exercise empty, truncated, tampered, existing-file, permission-denied, and failure-recovery cases where relevant.
- For serialization changes, test boundary lengths and forward/backward compatibility as needed.
- Do not silence security warnings just to make CI green. Clearly state what remains unverified.

## Commit history

Use short, scoped subjects such as `fix(cli): preserve old private keys on failure` or `test(crypto): add boundary cases`. Avoid force-pushing shared branches, changing published release tags, or rewriting `main` history. Completed and merged work branches can be deleted after verifying they contain no independent commits.

## Licensing

Review [LICENSE-AGPLv3.md](LICENSE-AGPLv3.md) and [LICENSE-PROPRIETARY.md](LICENSE-PROPRIETARY.md) before contributing. This guide does not alter either license or provide a commercial-license grant.
