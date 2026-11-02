# Portable Policy Kit

One known-good App Control base policy for every enclave (domain and OU) whose PAWs come from the same image. Copy the five files into `C:\WDAC\Source` on each enclave's reference device, check the hashes, then run the GPO flow. The steps and the guards are in [GPO README §3.1](../README.md#31-one-policy-kit-several-enclaves-domains-and-ous).

| File | Version | Audit Mode | Use |
|---|---|:---:|---|
| `Base-Enforce.xml` | `2026.11.2.2` | OFF | Step 1 builds both GPO packages from it |
| `Base-Audit-Merged.xml` | `2026.11.2.1` | ON | The same rules as `Base-Enforce.xml` in audit mode, for a later audit round (config guide) |
| `Base-Audit.xml` | `2026.10.21.1` | ON | The Wizard baseline without application rules, for a first audit round (config guide) |
| `PolicyGuid.txt` | `{75AFC1CF-5372-491A-80CA-7BBB694F0A00}` | | The same GUID in every enclave |
| `SHA256SUMS.txt` | | | SHA-256 of the four files above |

No rule names a user profile, and the kit contains no lab user, computer or domain name. The two FilePath rules for one lab user profile were removed on 2026-11-02. Step 1's portability gate refuses any policy that has such a rule.

Prove the kit and the flow in any domain, without changing anything, with [`../tests/Test-WdacGpoPortability.ps1`](../tests/Test-WdacGpoPortability.ps1).
