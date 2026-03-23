#!/usr/bin/env node
/**
 * scripts/tree_ci.js — Generate ceremony test vector input.json for CI
 *
 * Produces the standard ZKSN ceremony test vector:
 *   secret     = 12345678901234567890
 *   proposalId = 999888777666555
 *   voteYes    = 1
 *   treeIndex  = 0  (single-member depth-20 tree)
 *
 * Outputs JSON to stdout — used by ceremony_mainnet.yml to generate
 * ceremony/input.json without requiring tree state persistence.
 */

"use strict";

const { buildPoseidon } = require("circomlibjs");

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const DEPTH      = 20;
  const secret     = BigInt("12345678901234567890");
  const proposalId = BigInt("999888777666555");

  // Leaf 0 = Poseidon(secret), all others = 0
  const leaf = F.toObject(poseidon([secret]));

  // Precompute zero-subtree hashes
  const zeros = [0n];
  for (let d = 1; d <= DEPTH; d++) {
    zeros.push(F.toObject(poseidon([zeros[d-1], zeros[d-1]])));
  }

  // Merkle path for index 0: sibling at each level is the zero subtree hash
  const pathElements = [];
  const pathIndices  = [];
  let nodes = new Map([[0, leaf]]);
  let idx = 0;

  for (let d = 0; d < DEPTH; d++) {
    const sibIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    pathElements.push((nodes.get(sibIdx) ?? zeros[d]).toString());
    pathIndices.push((idx % 2).toString());

    // Promote to next level
    const next = new Map();
    for (const [i, v] of nodes) {
      const parent = Math.floor(i / 2);
      const sib    = nodes.get(i % 2 === 0 ? i + 1 : i - 1) ?? zeros[d];
      const left   = i % 2 === 0 ? v : sib;
      const right  = i % 2 === 0 ? sib : v;
      next.set(parent, F.toObject(poseidon([left, right])));
    }
    nodes = next;
    idx = Math.floor(idx / 2);
  }

  const root           = nodes.get(0) ?? zeros[DEPTH];
  const nullifierHash  = F.toObject(poseidon([secret, proposalId]));

  const input = {
    secret:         secret.toString(),
    pathElements,
    pathIndices,
    nullifierHash:  nullifierHash.toString(),
    proposalId:     proposalId.toString(),
    voteYes:        "1",
    membershipRoot: root.toString(),
  };

  process.stdout.write(JSON.stringify(input, null, 2) + "\n");
}

main().catch(e => { process.stderr.write(e.message + "\n"); process.exit(1); });
