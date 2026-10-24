# TrustVault — short project write-up

## What is built

TrustVault is a Flask document-sharing prototype with role-aware account management, private local file storage, document-level read/edit grants, revocation, metadata search, soft deletion, and a hash-linked audit event trail. It records successful and denied document access attempts and offers an administrative activity view.

## Permission model

A document owner can read, edit metadata, delete (soft delete), grant and revoke access to their own document. A named user with a `read` grant can download but cannot edit. A named user with an `edit` grant can download and edit metadata. Public registration always creates a viewer; an administrator can promote an account to owner/admin. Admin role is not a blanket bypass for file content. Every download rechecks the current database permission, so revocation blocks subsequent requests. Copies already downloaded cannot be recalled.

## AI use

Record the real prompts, output, errors found, corrections and commit hashes in `PROMPTS.md` as development proceeds. The current file contains planned examples and must be updated with genuine evidence before submission.

## Deliberate omissions

External guest links, expiring signed URLs, malware scanning, MFA/SSO, password reset, rate limiting, version history, recovery UI, independent immutable audit storage, external hash anchoring, full migration workflow and production backup/restore are not complete. The audit chain is tamper-evident only relative to a trusted checkpoint; a database administrator with full write access can rewrite the chain.

## Before submission

Run the full test suite, inspect the deployed app, verify every route, configure production secrets and private persistent storage, add migration and backup procedures, update `PROMPTS.md` with actual evidence, and publish a five-minute demo video. Do not claim production readiness without independent security review.
