# PatchProof live Studionet evidence

Network: GenLayer Studionet (`61999`)

Contract: [`0x85704ACF4212dC37D02697706d4FE83CbE5D0940`](https://explorer-studio.genlayer.com/address/0x85704ACF4212dC37D02697706d4FE83CbE5D0940)

Contract schema readback: `{"name":"PatchProof","schema":"semantic-security-remediation-v1","version":1}`

## Test identities and immutable sources

- Controller/maintainer: `0xeb57bc7125fa60d7482ce12058397369ab3581f8`
- Independent reviewer: `0x2da5393d7bbb9a037dc3abb56dbbc5c150fc843f`
- Project/case: `parser-muaobohp` / `pp-muaobohp`
- [Commit-pinned advisory](https://raw.githubusercontent.com/eaglebooth/PatchProof/d72d8428773a3b33ef406413a21a6cc0698c995d/fixtures/ADVISORY.md), SHA-256 `8ea1e9d5373b429e1236b72974fde75fd21d3bff0ecc94121b85cafec7d07aee`
- [Commit-pinned patch report](https://raw.githubusercontent.com/eaglebooth/PatchProof/d72d8428773a3b33ef406413a21a6cc0698c995d/fixtures/PATCH_REPORT.md), SHA-256 `d9e24312cff0a9f27002a1095599735eefa0ca93648f6c0e551662815c99767a`
- [Independent commit-pinned verification](https://raw.githubusercontent.com/eaglebooth/ForkRight/011fd33fbe6aa1fde66c8489c6ca3c7b282d6e36/docs/patchproof-independent-verification.md), SHA-256 `3b08705cb8bdb358262a83b95302f2b2728e27943916a805e11f3718cf7fcc23`

The files describe a synthetic parser vulnerability used only to exercise the contract. Authority came from the two on-chain addresses and registered policy, never from Markdown content.

## Finalized transaction ledger

Every transaction reached `FINALIZED`. Expected successes were checked against agreed validator result `SUCCESS`; expected rejection paths were checked against `ERROR`.

| Transition | Explorer | Result | Verified outcome |
|---|---|---|---|
| Register authority-bound project | [`0xb01a380c…d1a47`](https://explorer-studio.genlayer.com/tx/0xb01a380c5c0bde3fa76cd5e21e36b252876ea133a85131c54cffdc53333d1a47) | SUCCESS | Project policy and two roles recorded |
| Duplicate project | [`0x73582d88…a9b2f`](https://explorer-studio.genlayer.com/tx/0x73582d88610515ff0ca8d922b4a0499cadfe2701104d993d9a05fc790e7a9b2f) | ERROR | Duplicate namespace rejected |
| Open remediation case | [`0x3fbefb2d…0bb7c`](https://explorer-studio.genlayer.com/tx/0x3fbefb2d8b0e6c246b535a6a23d59976e55e7a15d9887dc1d29a4388e060bb7c) | SUCCESS | Advisory commitment recorded |
| Reviewer attempts patch submission | [`0x61e15963…d8b7`](https://explorer-studio.genlayer.com/tx/0x61e15963adec20feaa228a266b2a259b4fa4e62247fe351bd546469ccc14d8b7) | ERROR | `MAINTAINER_ONLY` enforced |
| Maintainer submits patch | [`0x10ad24cd…c4cb4`](https://explorer-studio.genlayer.com/tx/0x10ad24cdd3404e6baad8f12cb8fc33b039e2b97ad02c09b9c8db6891811c4cb4) | SUCCESS | Patch digest and nonce recorded |
| Assess before independent verification | [`0xfbd2d46c…bf513`](https://explorer-studio.genlayer.com/tx/0xfbd2d46c793ba8fbf22b27ee9e17bf570340c9cb108f876361dc0bc0a7abf513) | ERROR | `VERIFICATION_REQUIRED` enforced |
| Maintainer attempts reviewer submission | [`0xa0796eea…54454`](https://explorer-studio.genlayer.com/tx/0xa0796eeaef9377c6cf051cd2cd2171ffc28105cc5f8f1e42ccddde525c954454) | ERROR | `REVIEWER_ONLY` enforced |
| Reviewer submits independent verification | [`0x0939ad38…64d5d`](https://explorer-studio.genlayer.com/tx/0x0939ad38f4afbed204e1df345e56dca7d9e746bf8ad9cc3b2b10d5e79d364d5d) | SUCCESS | Distinct sender/repository evidence recorded |
| Semantic remediation assessment | [`0x1a21a1d3…da9b`](https://explorer-studio.genlayer.com/tx/0x1a21a1d311bc9fa9c214e8e578a0efcee0df13bd7dda594d816e4b627914da9b) | SUCCESS | Consensus returned `REMEDIATED` |
| Reviewer attempts receipt publication | [`0x1de5b9d6…cb6c`](https://explorer-studio.genlayer.com/tx/0x1de5b9d68fe19df94a719e8f5f5edfa539b4b392516766ab9c639658ea5dcb6c) | ERROR | Maintainer authority enforced |
| Publish remediation receipt | [`0xbeb9c6bb…c3c9`](https://explorer-studio.genlayer.com/tx/0xbeb9c6bb3a717c3d203558c9daca9c16f1e7e0017dd1daa75abddd333884c3c9) | SUCCESS | Single-use receipt published |
| Receipt replay | [`0x1c9ebaa1…8940`](https://explorer-studio.genlayer.com/tx/0x1c9ebaa1c9a5f87ff9d29f3a605dab7aae06617feb86a984f2172573ad158940) | ERROR | `RECEIPT_ALREADY_PUBLISHED` enforced |

## Canonical final state

- Verdict/status: `REMEDIATED / RECEIPT_PUBLISHED`
- Fixed version/affected range: `2.4.1 / <2.4.1`
- Assessment digest: `9d2f18c287755c147ea1ebbee7a8abe2e79f1b3a857859fcc0d1f670b2237426`
- Receipt: `bd773fab7083d85c7f172b11bf0abf7432c5d4afa459c168ddedf9b38470e503`
- `consumed=true`
- Contract stats after the run: `projects=1`, `cases=1`, `receipts=1`

The machine-readable record, including all assertions and exact source byte counts, is preserved in [`live-e2e-run.json`](./live-e2e-run.json).
