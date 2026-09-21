# PatchProof implementation plan

## Goal

Create a standalone Intelligent Contract that converts three independently sourced security documents into a single-use remediation receipt without treating Markdown as authority.

## Architecture

1. Controller registers maintainer/reviewer roles, repositories, and semantic policy on-chain.
2. Maintainer opens a case and commits advisory plus patch evidence.
3. Independent reviewer commits verification evidence from a distinct repository.
4. GenLayer validators compare all three sources under a bounded verdict schema.
5. Deterministic logic permits one receipt only for `REMEDIATED`.

## Verification

- Compile/deploy under `gltest`.
- Exercise happy, authorization, malformed-input, namespace, repository-scope, replay, and failure paths.
