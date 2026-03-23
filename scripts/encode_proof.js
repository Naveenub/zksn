#!/usr/bin/env node
/**
 * scripts/encode_proof.js — Encode a snarkjs proof.json to Solidity bytes
 *
 * Usage:
 *   node scripts/encode_proof.js ceremony/proof.json
 *
 * Output: 512 hex chars (256 bytes) ready for Solidity hex literal.
 *
 * snarkjs stores G2 Fp2 coordinates as [real, imaginary].
 * EIP-197 (bn128 precompile) requires [imaginary, real].
 * This script swaps them correctly.
 *
 * The output is printed as 8 × 64-char chunks for Solidity:
 *   bytes constant REAL_PROOF =
 *       hex"<chunk0>"
 *       hex"<chunk1>"
 *       ...
 *       hex"<chunk7>";
 */

"use strict";

const fs   = require("fs");
const path = require("path");

const proofPath = process.argv[2];
if (!proofPath) {
  console.error("Usage: node scripts/encode_proof.js <proof.json>");
  process.exit(1);
}

const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));

function toHex32(n) {
  const h = BigInt(n).toString(16).padStart(64, "0");
  if (h.length !== 64) throw new Error("Bad field element: " + n);
  return h;
}

// pA: [x, y]
const pA_x = toHex32(proof.pi_a[0]);
const pA_y = toHex32(proof.pi_a[1]);

// pB: EIP-197 requires Fp2 as (imaginary, real).
// snarkjs proof.json stores pi_b[i] as [real, imaginary] — swap indices.
const pB_x_im = toHex32(proof.pi_b[0][1]); // [0][1] = imaginary → slot 0
const pB_x_re = toHex32(proof.pi_b[0][0]); // [0][0] = real      → slot 1
const pB_y_im = toHex32(proof.pi_b[1][1]); // [1][1] = imaginary → slot 2
const pB_y_re = toHex32(proof.pi_b[1][0]); // [1][0] = real      → slot 3

// pC: [x, y]
const pC_x = toHex32(proof.pi_c[0]);
const pC_y = toHex32(proof.pi_c[1]);

const chunks = [pA_x, pA_y, pB_x_im, pB_x_re, pB_y_im, pB_y_re, pC_x, pC_y];

// Validate — every chunk must be exactly 64 hex chars (32 bytes)
chunks.forEach((c, i) => {
  if (c.length !== 64) throw new Error(`Chunk ${i} is ${c.length} chars, expected 64`);
});

const totalBytes = chunks.join("").length / 2;
if (totalBytes !== 256) throw new Error(`Expected 256 bytes, got ${totalBytes}`);

console.log(`// proof.json: ${path.basename(proofPath)}`);
console.log(`// Total: ${totalBytes} bytes (${chunks.join("").length} hex chars)`);
console.log(``);
console.log(`bytes constant REAL_PROOF =`);
chunks.forEach((c, i) => {
  const comma = i === chunks.length - 1 ? ";" : "";
  console.log(`    hex"${c}"${comma}`);
});
console.log(``);
console.log(`// Public signals (from public.json):`);
console.log(`// [0] nullifierHash  = ?`);
console.log(`// [1] proposalId     = ?`);
console.log(`// [2] voteYes        = ?`);
console.log(`// [3] membershipRoot = ?   ← use as REAL_MEMBERSHIP_ROOT`);
