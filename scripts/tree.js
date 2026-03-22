#!/usr/bin/env node
/**
 * scripts/tree.js — ZKSN Poseidon membership tree builder (depth-20)
 *
 * Builds a depth-20 Poseidon Merkle tree supporting up to 2^20 = 1,048,576
 * members. Hash outputs are bit-for-bit identical to the on-chain PoseidonHasher
 * contract and the MembershipVote circuit (circomlib poseidon.circom).
 *
 * Usage:
 *   node scripts/tree.js add    <secret>                          # add voter
 *   node scripts/tree.js root                                     # print root
 *   node scripts/tree.js proof  <secret>                         # Merkle path
 *   node scripts/tree.js input  <secret> <proposalId> <voteYes>  # circuit input.json
 *   node scripts/tree.js verify <secret>                         # check membership
 *
 * State is persisted to tree_state.json in the working directory.
 *
 * Full anonymous vote flow:
 *   1. node scripts/tree.js add 12345678901234567890
 *   2. node scripts/tree.js root
 *        → submit root to ZKSNGovernance.updateMembershipRoot(root)
 *   3. node scripts/tree.js input 12345678901234567890 999888777666555 1 > input.json
 *   4. node build/MembershipVote_js/generate_witness.js \
 *          build/MembershipVote_js/MembershipVote.wasm input.json witness.wtns
 *   5. npx snarkjs groth16 prove ceremony/zkey_final.zkey witness.wtns proof.json public.json
 *   6. encode proof + call ZKSNGovernance.castVote(proposalId, nullifierHash, true, proofBytes)
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");

const DEPTH      = 20;
const TREE_SIZE  = 1 << DEPTH; // 1,048,576
const STATE_FILE = path.join(process.cwd(), "tree_state.json");

// ── Poseidon ──────────────────────────────────────────────────────────────────

async function getPoseidon() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  return {
    hash1: (a)    => F.toObject(poseidon([BigInt(a)])),
    hash2: (a, b) => F.toObject(poseidon([BigInt(a), BigInt(b)])),
  };
}

// ── Zero-value cache (empty subtree hashes) ───────────────────────────────────
// zeros[d] = hash of an all-zero subtree at depth d
// zeros[0] = 0 (empty leaf)
// zeros[d] = Poseidon(zeros[d-1], zeros[d-1])
// Precomputed once per tree instance. Allows O(log N) root computation for
// sparse trees without materialising all 1M leaves.

async function buildZeros(poseidon) {
  const z = [0n];
  for (let d = 1; d <= DEPTH; d++) {
    z.push(poseidon.hash2(z[d-1], z[d-1]));
  }
  return z;
}

// ── State ─────────────────────────────────────────────────────────────────────

function loadState() {
  if (fs.existsSync(STATE_FILE)) {
    const raw = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    return {
      // sparse: only non-zero leaf indices stored
      leafMap: new Map(Object.entries(raw.leafMap).map(([k,v]) => [parseInt(k), BigInt(v)])),
      secrets: raw.secrets.map(BigInt),
    };
  }
  return { leafMap: new Map(), secrets: [] };
}

function saveState(state) {
  const leafObj = {};
  for (const [k, v] of state.leafMap) leafObj[k] = v.toString();
  fs.writeFileSync(STATE_FILE, JSON.stringify({
    leafMap: leafObj,
    secrets: state.secrets.map(String),
  }, null, 2));
}

// ── Sparse Merkle root ────────────────────────────────────────────────────────

async function computeRoot(leafMap, poseidon, zeros) {
  // Bottom-up: at each level, only compute nodes that have at least one non-zero
  // leaf in their subtree. Everything else uses the precomputed zero hash.
  let nodes = new Map(leafMap);
  for (let d = 0; d < DEPTH; d++) {
    const next = new Map();
    // gather all parent indices that have at least one non-zero child
    const parents = new Set([...nodes.keys()].map(i => Math.floor(i / 2)));
    for (const p of parents) {
      const left  = nodes.get(p * 2)     ?? zeros[d];
      const right = nodes.get(p * 2 + 1) ?? zeros[d];
      next.set(p, poseidon.hash2(left, right));
    }
    nodes = next;
  }
  return nodes.get(0) ?? zeros[DEPTH];
}

// ── Merkle proof ──────────────────────────────────────────────────────────────

async function getMerkleProof(leafMap, index, poseidon, zeros) {
  // Build path from leaf to root
  const pathElements = [];
  const pathIndices  = [];
  let nodes = new Map(leafMap);

  for (let d = 0; d < DEPTH; d++) {
    const sibIdx = index % 2 === 0 ? index + 1 : index - 1;
    pathElements.push(nodes.get(sibIdx) ?? zeros[d]);
    pathIndices.push(index % 2);

    // Promote level
    const next = new Map();
    const parents = new Set([...nodes.keys()].map(i => Math.floor(i / 2)));
    for (const p of parents) {
      const left  = nodes.get(p * 2)     ?? zeros[d];
      const right = nodes.get(p * 2 + 1) ?? zeros[d];
      next.set(p, poseidon.hash2(left, right));
    }
    nodes = next;
    index = Math.floor(index / 2);
  }

  return { pathElements, pathIndices, root: nodes.get(0) ?? zeros[DEPTH] };
}

// ── CLI commands ──────────────────────────────────────────────────────────────

async function cmdAdd(secret) {
  const poseidon  = await getPoseidon();
  const zeros     = await buildZeros(poseidon);
  const state     = loadState();
  const secretBig = BigInt(secret);

  if (state.secrets.some(s => s === secretBig)) {
    console.error("Error: secret already in tree"); process.exit(1);
  }
  if (state.secrets.length >= TREE_SIZE) {
    console.error(`Error: tree full (max ${TREE_SIZE})`); process.exit(1);
  }

  const index = state.secrets.length;
  const leaf  = poseidon.hash1(secretBig);
  state.leafMap.set(index, leaf);
  state.secrets.push(secretBig);
  saveState(state);

  const root = await computeRoot(state.leafMap, poseidon, zeros);
  console.log(JSON.stringify({ index, leaf: leaf.toString(), root: root.toString() }, null, 2));
}

async function cmdRoot() {
  const poseidon = await getPoseidon();
  const zeros    = await buildZeros(poseidon);
  const state    = loadState();
  const root     = await computeRoot(state.leafMap, poseidon, zeros);
  console.log(root.toString());
}

async function cmdProof(secret) {
  const poseidon  = await getPoseidon();
  const zeros     = await buildZeros(poseidon);
  const state     = loadState();
  const secretBig = BigInt(secret);
  const index     = state.secrets.findIndex(s => s === secretBig);

  if (index === -1) { console.error("Error: secret not in tree"); process.exit(1); }

  const { pathElements, pathIndices, root } =
    await getMerkleProof(state.leafMap, index, poseidon, zeros);

  console.log(JSON.stringify({
    index,
    root:         root.toString(),
    pathElements: pathElements.map(String),
    pathIndices:  pathIndices.map(String),
  }, null, 2));
}

async function cmdInput(secret, proposalId, voteYes) {
  const poseidon  = await getPoseidon();
  const zeros     = await buildZeros(poseidon);
  const state     = loadState();
  const secretBig = BigInt(secret);
  const index     = state.secrets.findIndex(s => s === secretBig);

  if (index === -1) {
    console.error("Error: secret not in tree. Run: node scripts/tree.js add <secret>");
    process.exit(1);
  }

  const { pathElements, pathIndices, root } =
    await getMerkleProof(state.leafMap, index, poseidon, zeros);
  const nullifierHash = poseidon.hash2(secretBig, BigInt(proposalId));

  const input = {
    secret:         secretBig.toString(),
    pathElements:   pathElements.map(String),
    pathIndices:    pathIndices.map(String),
    nullifierHash:  nullifierHash.toString(),
    proposalId:     BigInt(proposalId).toString(),
    voteYes:        voteYes === "1" ? "1" : "0",
    membershipRoot: root.toString(),
  };
  console.log(JSON.stringify(input, null, 2));
}

async function cmdVerify(secret) {
  const poseidon  = await getPoseidon();
  const zeros     = await buildZeros(poseidon);
  const state     = loadState();
  const secretBig = BigInt(secret);
  const index     = state.secrets.findIndex(s => s === secretBig);

  if (index === -1) { console.log("NOT IN TREE"); process.exit(1); }

  const root = await computeRoot(state.leafMap, poseidon, zeros);
  console.log(JSON.stringify({ member: true, index, root: root.toString() }, null, 2));
}

// ── Entry point ───────────────────────────────────────────────────────────────

(async () => {
  const [,, cmd, ...args] = process.argv;
  switch (cmd) {
    case "add":    await cmdAdd(args[0]); break;
    case "root":   await cmdRoot(); break;
    case "proof":  await cmdProof(args[0]); break;
    case "input":  await cmdInput(args[0], args[1], args[2]); break;
    case "verify": await cmdVerify(args[0]); break;
    default:
      console.error("Usage: node scripts/tree.js {add|root|proof|input|verify} [args...]");
      process.exit(1);
  }
})().catch(e => { console.error(e); process.exit(1); });
