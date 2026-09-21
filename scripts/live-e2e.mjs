import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { createAccount, createClient } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
};
const account = (name) => createAccount(`0x${required(name).replace(/^0x/, "")}`);
const contract = required("CONTRACT_ADDRESS");
const maintainer = account("MAINTAINER_KEY");
const reviewer = account("REVIEWER_KEY");
const maintainerClient = createClient({ chain: studionet, account: maintainer });
const reviewerClient = createClient({ chain: studionet, account: reviewer });
const run = process.env.RUN_ID || Date.now().toString(36);
const ids = { project: `parser-${run}`, case: `pp-${run}` };

const patchCommit = "d72d8428773a3b33ef406413a21a6cc0698c995d";
const reviewCommit = "011fd33fbe6aa1fde66c8489c6ca3c7b282d6e36";
const urls = {
  advisory: `https://raw.githubusercontent.com/eaglebooth/PatchProof/${patchCommit}/fixtures/ADVISORY.md`,
  patch: `https://raw.githubusercontent.com/eaglebooth/PatchProof/${patchCommit}/fixtures/PATCH_REPORT.md`,
  verification: `https://raw.githubusercontent.com/eaglebooth/ForkRight/${reviewCommit}/docs/patchproof-independent-verification.md`,
};
const report = {
  contract,
  network: "studionet-61999",
  actors: { controllerMaintainer: maintainer.address, reviewer: reviewer.address },
  ids,
  sources: {},
  transactions: [],
  assertions: [],
  final: {},
};

mkdirSync("docs", { recursive: true });
const save = () => writeFileSync("docs/live-e2e-run.json", `${JSON.stringify(report, null, 2)}\n`);
const source = async (url) => {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Source fetch failed ${response.status}: ${url}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  return { url, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
};
for (const [name, url] of Object.entries(urls)) report.sources[name] = await source(url);

const read = async (method, args = []) => JSON.parse(await maintainerClient.readContract({ address: contract, functionName: method, args }));
const check = (condition, label, details = {}) => {
  report.assertions.push({ label, pass: Boolean(condition), details });
  save();
  if (!condition) throw new Error(`Assertion failed: ${label}: ${JSON.stringify(details)}`);
};
const executionOf = (tx) => {
  const results = (tx.consensus_data?.validators || []).filter((v) => v.vote === "agree").map((v) => v.execution_result);
  return results.includes("SUCCESS") ? "SUCCESS" : results.includes("ERROR") ? "ERROR" : "UNKNOWN";
};
const write = async (label, client, method, args, expected = "SUCCESS") => {
  let hash;
  try {
    hash = await client.writeContract({ address: contract, functionName: method, args, value: 0n });
  } catch (error) {
    if (expected !== "ROLLBACK") throw error;
    report.transactions.push({ label, hash: null, expected, status: "PRECHECK_REJECTED", execution: "ERROR", error: error instanceof Error ? error.message : String(error) });
    check(true, `${label} rejected before signing`);
    return null;
  }
  process.stdout.write(`${label}: ${hash}\n`);
  let tx = {};
  for (let attempt = 0; attempt < 300; attempt += 1) {
    tx = await client.getTransaction({ hash });
    if (["FINALIZED", "CANCELED", "UNDETERMINED"].includes(tx.statusName)) break;
    await new Promise((resolve) => setTimeout(resolve, 2500));
  }
  const execution = executionOf(tx);
  report.transactions.push({ label, hash, expected, status: tx.statusName || "UNKNOWN", execution });
  save();
  if (expected === "SUCCESS") check(execution === "SUCCESS", `${label} succeeded in GenVM`, { execution, status: tx.statusName });
  else check(execution === "ERROR", `${label} reverted in GenVM`, { execution, status: tx.statusName });
  return hash;
};

const version = await read("get_contract_version");
check(version.name === "PatchProof" && version.version === 1, "deployed PatchProof V1 schema", version);
const policy = "A remediation must match the advisory root cause and affected range, include regression tests, document residual risk, and be independently reproduced before a receipt can be published.";
await write("register authority-bound project", maintainerClient, "register_project", [ids.project, maintainer.address, reviewer.address, "eaglebooth/patchproof", "eaglebooth/forkright", policy]);
await write("reject duplicate project", maintainerClient, "register_project", [ids.project, maintainer.address, reviewer.address, "eaglebooth/patchproof", "eaglebooth/forkright", policy], "ROLLBACK");
const advisory = report.sources.advisory;
await write("open remediation case", maintainerClient, "open_case", [maintainer.address, ids.project, ids.case, advisory.url, advisory.sha256, BigInt(advisory.bytes), "2.4.1", "<2.4.1"]);
const patch = report.sources.patch;
await write("reject reviewer patch submission", reviewerClient, "submit_patch", [maintainer.address, ids.project, ids.case, patch.url, patch.sha256, BigInt(patch.bytes), `bad-${run}`], "ROLLBACK");
await write("submit maintainer patch", maintainerClient, "submit_patch", [maintainer.address, ids.project, ids.case, patch.url, patch.sha256, BigInt(patch.bytes), `patch-${run}`]);
await write("reject assessment before verification", maintainerClient, "assess_case", [maintainer.address, ids.project, ids.case], "ROLLBACK");
const verification = report.sources.verification;
await write("reject maintainer verification", maintainerClient, "submit_verification", [maintainer.address, ids.project, ids.case, verification.url, verification.sha256, BigInt(verification.bytes), `bad-verify-${run}`], "ROLLBACK");
await write("submit independent verification", reviewerClient, "submit_verification", [maintainer.address, ids.project, ids.case, verification.url, verification.sha256, BigInt(verification.bytes), `verify-${run}`]);
await write("assess semantic remediation", maintainerClient, "assess_case", [maintainer.address, ids.project, ids.case]);
let state = await read("get_case", [maintainer.address, ids.project, ids.case]);
check(state.verdict === "REMEDIATED" && state.status === "ASSESSED", "consensus confirmed remediation", state);
await write("reject reviewer receipt publication", reviewerClient, "publish_receipt", [maintainer.address, ids.project, ids.case, state.assessment_digest], "ROLLBACK");
await write("publish remediation receipt", maintainerClient, "publish_receipt", [maintainer.address, ids.project, ids.case, state.assessment_digest]);
await write("reject receipt replay", maintainerClient, "publish_receipt", [maintainer.address, ids.project, ids.case, state.assessment_digest], "ROLLBACK");
state = await read("get_case", [maintainer.address, ids.project, ids.case]);
check(state.status === "RECEIPT_PUBLISHED" && state.consumed && state.receipt?.length === 64, "receipt finalized and consumed once", state);
report.final = { project: await read("get_project", [maintainer.address, ids.project]), case: state, stats: await read("get_stats") };
save();
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
