# Five-minute demo outline

1. **0:00–0:30 — Problem and roles.** Introduce TrustVault and explain that UI hiding is not authorization.
2. **0:30–1:15 — Owner workflow.** Sign in as an owner, upload a harmless sample PDF/TXT, and show the document listing and search filters.
3. **1:15–2:00 — Share.** Grant a second account read permission; sign in as that user and download the file.
4. **2:00–2:45 — Attack and revoke.** Attempt a direct download as an unrelated user and show it is denied. Revoke the grantee, repeat the same URL and show it is denied.
5. **2:45–3:30 — Edit boundary.** Show read-only users cannot change metadata, while an edit grantee can.
6. **3:30–4:15 — Audit.** Show successful and denied events, permission changes, and the audit chain verification status.
7. **4:15–5:00 — Honest limitations.** Explain external anchoring, malware scanning, MFA, backups and immutable storage as unfinished work.

Use only non-sensitive demo files and demo accounts. Do not show secrets or real customer documents.
