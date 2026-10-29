# Security Policy

## Project status

OracipherCore is an **alpha-stage cryptographic project**. Do not assume it has undergone a comprehensive independent security audit, or use it as the sole protection for irreplaceable or production secrets without an appropriate assessment.

For a known issue list, review the repository's open [Issues](https://github.com/Oracipher/OracipherCore/issues), especially issues labeled or titled with security and data loss.

## Reporting a vulnerability

**Please do not post exploit details, secret material, or sensitive affected user data in a public issue.**

If GitHub's private vulnerability reporting feature is available for this repository, go to **Security → Advisories → Report a vulnerability** and provide the technical details privately. Otherwise, contact the repository maintainers through a private communication channel before publicly disclosing the issue.

A useful private report contains:

- Affected commit SHA, platform, compiler, and dependency versions.
- A minimal reproducer, expected versus observed behavior, and suspected impact.
- Whether the issue can lead to plaintext disclosure, key loss, memory corruption, or forged authentication.
- Any relevant sanitized logs (remove secrets and real private keys).

Do not upload an actual private key, production pepper, password, or decrypted confidential file to GitHub.

## Update and response expectations

No fixed response time, supported release range, or security-fix SLA is currently promised. A finding should be confirmed, remediated, reviewed, and tested before maintainers claim that it has been resolved. When an update changes a cryptographic file format or breaks compatibility, document that explicitly.
