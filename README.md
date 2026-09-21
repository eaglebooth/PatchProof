# PatchProof

PatchProof is a GenLayer Intelligent Contract that publishes verifiable security-remediation receipts. Authority comes exclusively from `gl.message.sender_address` and a project policy stored on-chain. Markdown files are immutable, commit-pinned evidence; they never grant authority.

## Why intelligent consensus matters

Security fixes rarely reduce to an exact string comparison. PatchProof asks validators to compare an advisory, a maintainer's patch report, and an independent reproduction report for semantic agreement about root cause, affected versions, regression coverage, residual risk, and the claimed fixed version. Deterministic contract logic then gates the receipt on the bounded `REMEDIATED` verdict.

## State machine

`OPEN -> PATCH_SUBMITTED -> READY_FOR_ASSESSMENT -> ASSESSED -> RECEIPT_PUBLISHED`

Non-remediated verdicts remain `ASSESSED` and cannot publish a receipt.

## Authority and evidence model

- The deploying/calling controller registers a project policy.
- Only the on-chain maintainer address can open cases, submit patches, and publish receipts.
- Only the distinct on-chain reviewer address can submit independent verification; the reviewer cannot be the maintainer or controller.
- Maintainer and reviewer repositories must differ.
- Evidence URLs must use `raw.githubusercontent.com/{owner}/{repo}/{40-char-commit}/...md`.
- SHA-256, exact byte length, scoped nonces, and semantic assessment are checked before a receipt is issued.
- `UNAVAILABLE` does not finalize a case, so transient source/model failures can be retried.

## Public methods

- `register_project`
- `open_case`
- `submit_patch`
- `submit_verification`
- `assess_case`
- `publish_receipt`
- `get_project`, `get_case`, `get_stats`, `get_contract_version`

## Test

```bash
python -m pytest -q -p no:cacheprovider
```

The behavioral suite covers schema/deployment, malformed inputs, namespace isolation, sender authorization, repository scoping, full remediation, receipt replay, and a non-remediated rejection path.

## Studio deployment

Deploy `contracts/patchproof.py` in GenLayer Studio. After deployment, use two distinct accounts for maintainer and reviewer and replace the fixture URLs with raw GitHub URLs pinned to the commit containing the exact files.
