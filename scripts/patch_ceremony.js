#!/usr/bin/env node
/**
 * scripts/patch_ceremony.js — Patch Groth16Verifier.sol and ZKSNGovernance.t.sol
 * with fresh constants from a completed snarkjs ceremony.
 *
 * Reads:
 *   ceremony/verification_key.json  — new VK from zkey_final
 *   ceremony/proof.json             — ceremony test proof
 *   ceremony/public.json            — public signals [nullifier, proposalId, voteYes, root]
 *
 * Writes (in-place):
 *   governance/contracts/Groth16Verifier.sol  — all VK constants
 *   governance/test/ZKSNGovernance.t.sol      — REAL_PROOF, REAL_MEMBERSHIP_ROOT
 *
 * Run:
 *   node scripts/patch_ceremony.js
 *   node scripts/patch_ceremony.js --dry-run   # print diffs, write nothing
 *
 * Used by .github/workflows/ceremony_mainnet.yml after each ceremony run.
 */

"use strict";

const fs   = require("fs");
const path = require("path");

const DRY_RUN = process.argv.includes("--dry-run");

// ── Paths ─────────────────────────────────────────────────────────────────────

const ROOT     = path.resolve(__dirname, "..");
const VK_PATH  = path.join(ROOT, "ceremony", "verification_key.json");
const PROOF_PATH   = path.join(ROOT, "ceremony", "proof.json");
const PUBLIC_PATH  = path.join(ROOT, "ceremony", "public.json");
const VERIFIER_SOL = path.join(ROOT, "governance", "contracts", "Groth16Verifier.sol");
const TEST_SOL     = path.join(ROOT, "governance", "test", "ZKSNGovernance.t.sol");

// ── Helpers ───────────────────────────────────────────────────────────────────

function read(p) {
  if (!fs.existsSync(p)) throw new Error(`Missing file: ${p}`);
  return fs.readFileSync(p, "utf8");
}

function write(p, content, original) {
  if (DRY_RUN) {
    console.log(`\n[dry-run] Would write ${path.relative(ROOT, p)}`);
    const oLines = original.split("\n");
    const nLines = content.split("\n");
    let changes = 0;
    for (let i = 0; i < Math.max(oLines.length, nLines.length); i++) {
      if (oLines[i] !== nLines[i]) {
        console.log(`  - ${oLines[i] || ""}`);
        console.log(`  + ${nLines[i] || ""}`);
        changes++;
        if (changes > 30) { console.log("  ... (truncated)"); break; }
      }
    }
  } else {
    fs.writeFileSync(p, content, "utf8");
    console.log(`✅ Patched: ${path.relative(ROOT, p)}`);
  }
}

function replaceConst(sol, name, value) {
  // Matches: uint256 constant <name> = <anything>;
  const re = new RegExp(`(uint256 constant ${name}\\s*=\\s*)([^;]+)(;)`, "g");
  const result = sol.replace(re, `$1${value}$3`);
  if (result === sol) throw new Error(`Constant not found: ${name}`);
  return result;
}

function toHex32(n) {
  const h = BigInt(n).toString(16).padStart(64, "0");
  if (h.length !== 64) throw new Error(`Bad field element for hex32: ${n}`);
  return h;
}

// ── Load ceremony outputs ─────────────────────────────────────────────────────

console.log("Loading ceremony outputs...");
const vk     = JSON.parse(read(VK_PATH));
const proof  = JSON.parse(read(PROOF_PATH));
const pubSig = JSON.parse(read(PUBLIC_PATH));

// public.json = [nullifierHash, proposalId, voteYes, membershipRoot]
const REAL_NULLIFIER      = pubSig[0];
const REAL_MEMBERSHIP_ROOT = pubSig[3];

console.log(`  nullifierHash  : ${REAL_NULLIFIER}`);
console.log(`  membershipRoot : ${REAL_MEMBERSHIP_ROOT}`);

// ── Extract VK constants ──────────────────────────────────────────────────────

// vk_alpha_1: [x, y, 1]
const alphax = vk.vk_alpha_1[0];
const alphay = vk.vk_alpha_1[1];

// vk_beta_2 / gamma_2 / delta_2: snarkjs VK stores Fp2 as [imaginary, real].
// Solidity constants use: x1 = real ([1]), x2 = imaginary ([0]).
const betax1 = vk.vk_beta_2[0][1];   // real   → betax1
const betax2 = vk.vk_beta_2[0][0];   // imag   → betax2
const betay1 = vk.vk_beta_2[1][1];
const betay2 = vk.vk_beta_2[1][0];

// vk_gamma_2: same layout
const gammax1 = vk.vk_gamma_2[0][1];
const gammax2 = vk.vk_gamma_2[0][0];
const gammay1 = vk.vk_gamma_2[1][1];
const gammay2 = vk.vk_gamma_2[1][0];

// vk_delta_2: same layout
const deltax1 = vk.vk_delta_2[0][1];
const deltax2 = vk.vk_delta_2[0][0];
const deltay1 = vk.vk_delta_2[1][1];
const deltay2 = vk.vk_delta_2[1][0];

// IC[i]: [x, y, 1]
const IC = vk.IC;
if (IC.length !== 5) throw new Error(`Expected 5 IC points, got ${IC.length}`);

console.log(`  deltax1        : ${deltax1}`);
console.log(`  IC[0]          : (${IC[0][0]}, ${IC[0][1]})`);

// ── Encode proof to EIP-197 hex ───────────────────────────────────────────────

// pA: [x, y]
const pA_x = toHex32(proof.pi_a[0]);
const pA_y = toHex32(proof.pi_a[1]);

// pB: snarkjs proof.json stores pi_b[i] as [real, imaginary]
// EIP-197 requires Fp2 as (imaginary, real) — swap indices
const pB_x_im = toHex32(proof.pi_b[0][1]);
const pB_x_re = toHex32(proof.pi_b[0][0]);
const pB_y_im = toHex32(proof.pi_b[1][1]);
const pB_y_re = toHex32(proof.pi_b[1][0]);

// pC: [x, y]
const pC_x = toHex32(proof.pi_c[0]);
const pC_y = toHex32(proof.pi_c[1]);

const chunks = [pA_x, pA_y, pB_x_im, pB_x_re, pB_y_im, pB_y_re, pC_x, pC_y];
chunks.forEach((c, i) => {
  if (c.length !== 64) throw new Error(`Chunk ${i} is ${c.length} chars, expected 64`);
});

const proofLines = chunks
  .map((c, i) => `        hex"${c}"${i === 7 ? ";" : ""}`)
  .join("\n");

// ── Patch Groth16Verifier.sol ─────────────────────────────────────────────────

console.log("\nPatching Groth16Verifier.sol...");
let sol = read(VERIFIER_SOL);
const solOrig = sol;

// Update all VK constants
for (const [name, val] of [
  ["alphax",  alphax],  ["alphay",  alphay],
  ["betax1",  betax1],  ["betax2",  betax2],
  ["betay1",  betay1],  ["betay2",  betay2],
  ["gammax1", gammax1], ["gammax2", gammax2],
  ["gammay1", gammay1], ["gammay2", gammay2],
  ["deltax1", deltax1], ["deltax2", deltax2],
  ["deltay1", deltay1], ["deltay2", deltay2],
  ["IC0x", IC[0][0]], ["IC0y", IC[0][1]],
  ["IC1x", IC[1][0]], ["IC1y", IC[1][1]],
  ["IC2x", IC[2][0]], ["IC2y", IC[2][1]],
  ["IC3x", IC[3][0]], ["IC3y", IC[3][1]],
  ["IC4x", IC[4][0]], ["IC4y", IC[4][1]],
]) {
  sol = replaceConst(sol, name, val);
}

// Update comment header lines
sol = sol
  .replace(
    /Generated from: MembershipVote\.circom \(depth=\d+\), [^\n]+/,
    "Generated from: MembershipVote.circom (depth=20), powersOfTau28_hez_final_15.ptau"
  )
  .replace(
    /Ceremony: [^\n]+/,
    "Ceremony: 3-contributor MPC + random beacon — Hermez pot28 (1000+ contributors)."
  )
  .replace(
    /Verification Key — MembershipVote\(depth=\d+\)/,
    "Verification Key — MembershipVote(depth=20)"
  );

write(VERIFIER_SOL, sol, solOrig);

// ── Patch ZKSNGovernance.t.sol ────────────────────────────────────────────────

console.log("\nPatching ZKSNGovernance.t.sol...");
let test = read(TEST_SOL);
const testOrig = test;

// Replace REAL_PROOF block
// Locate the declaration line, then find the last hex"..." line (ends with ";")
// and splice the new 8-chunk block in.
{
  const DECL = "    bytes constant REAL_PROOF =";
  const start = test.indexOf(DECL);
  if (start === -1) throw new Error("REAL_PROOF not found in test file");
  // Find the semicolon that closes the last hex literal
  let searchFrom = start + DECL.length;
  let lastHexEnd = -1;
  let hexPos = test.indexOf('hex"', searchFrom);
  while (hexPos !== -1 && hexPos - start < 600) {
    const semi = test.indexOf(";", hexPos);
    if (semi !== -1) lastHexEnd = semi + 1;
    hexPos = test.indexOf('hex"', hexPos + 1);
  }
  if (lastHexEnd === -1) throw new Error("Could not find end of REAL_PROOF block");
  const newBlock = `    bytes constant REAL_PROOF =\n${proofLines}`;
  test = test.slice(0, start) + newBlock + test.slice(lastHexEnd);
}

// Replace REAL_NULLIFIER (may be single-line or two-line)
// Canonical form: uint256 constant REAL_NULLIFIER =\n        <value>;
test = test.replace(
  /uint256 constant REAL_NULLIFIER\s*=\s*[\n\s]*\d+;/,
  `uint256 constant REAL_NULLIFIER =\n        ${REAL_NULLIFIER};`
);

// Replace REAL_MEMBERSHIP_ROOT
test = test.replace(
  /uint256 constant REAL_MEMBERSHIP_ROOT\s*=\s*[\n\s]*\d+;/,
  `uint256 constant REAL_MEMBERSHIP_ROOT =\n        ${REAL_MEMBERSHIP_ROOT};`
);

// Update ceremony comment in test
test = test
  .replace(
    /\/\/ Proof from ZKSN 3-contributor MPC ceremony — [^\n]+/,
    "// Proof from ZKSN 3-contributor MPC ceremony — MembershipVote(depth=20), pot28 (Hermez 1000+)."
  )
  .replace(
    /\/\/ Circuit: MembershipVote \(depth=\d+, \d+ constraints\)/,
    "// Circuit: MembershipVote (depth=20, 5360 constraints)"
  );

write(TEST_SOL, test, testOrig);

// ── Summary ───────────────────────────────────────────────────────────────────

console.log("\n=== Ceremony patch complete ===");
console.log(`  REAL_NULLIFIER       : ${REAL_NULLIFIER}`);
console.log(`  REAL_MEMBERSHIP_ROOT : ${REAL_MEMBERSHIP_ROOT}`);
console.log(`  REAL_PROPOSAL_ID     : 999888777666555 (unchanged)`);
if (DRY_RUN) {
  console.log("\n[dry-run] No files were written.");
} else {
  console.log("\nNext steps:");
  console.log("  forge test   — all 47 tests must pass");
  console.log("  Update ceremony/ATTESTATION.md with contribution hashes");
}
