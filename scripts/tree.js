#!/usr/bin/env node
/**
 * scripts/tree.js — ZKSN Poseidon membership tree builder
 *
 * Builds a depth-4 (16-member) Poseidon Merkle tree matching the on-chain
 * PoseidonHasher contract and the MembershipVote circuit exactly.
 *
 * Usage:
 *   node scripts/tree.js add    <secret>              # add member
 *   node scripts/tree.js root                         # print current root
 *   node scripts/tree.js proof  <secret>              # generate Merkle proof
 *   node scripts/tree.js input  <secret> <proposalId> <voteYes> # full circuit input
 *   node scripts/tree.js verify <secret>              # verify membership
 *
 * The tree state is persisted to tree_state.json in the working directory.
 *
 * Example full flow:
 *   node scripts/tree.js add    12345678901234567890
 *   node scripts/tree.js input  12345678901234567890 999888777666555 1 > input.json
 *   npx snarkjs groth16 prove zkey_final.zkey witness.wtns proof.json public.json
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");

const DEPTH       = 4;
const TREE_SIZE   = 1 << DEPTH; // 16
const STATE_FILE  = path.join(process.cwd(), "tree_state.json");

// ── Poseidon wrappers ─────────────────────────────────────────────────────────

async function getPoseidon() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  return {
    hash1: (a)    => F.toObject(poseidon([BigInt(a)])),
    hash2: (a, b) => F.toObject(poseidon([BigInt(a), BigInt(b)])),
  };
}

// ── State ─────────────────────────────────────────────────────────────────────

function loadState() {
  if (fs.existsSync(STATE_FILE)) {
    const raw = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    return {
      leaves: raw.leaves.map(BigInt),
      secrets: raw.secrets.map(BigInt),
    };
  }
  return {
    leaves:  new Array(TREE_SIZE).fill(0n),
    secrets: [],
  };
}

function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify({
    leaves:  state.leaves.map(String),
    secrets: state.secrets.map(String),
  }, null, 2));
}

// ── Tree operations ───────────────────────────────────────────────────────────

async function buildTree(leaves, poseidon) {
  let levels = [leaves.slice()];
  for (let d = 0; d < DEPTH; d++) {
    const prev = levels[d];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      next.push(poseidon.hash2(prev[i], prev[i + 1]));
    }
    levels.push(next);
  }
  return levels; // levels[0] = leaves, levels[DEPTH] = [root]
}

async function getRoot(leaves, poseidon) {
  const levels = await buildTree(leaves, poseidon);
  return levels[DEPTH][0];
}

async function getMerkleProof(leaves, index, poseidon) {
  const levels = await buildTree(leaves, poseidon);
  const pathElements = [];
  const pathIndices  = [];
  let idx = index;
  for (let d = 0; d < DEPTH; d++) {
    const sibling = idx % 2 === 0 ? levels[d][idx + 1] : levels[d][idx - 1];
    pathElements.push(sibling);
    pathIndices.push(idx % 2);
    idx = Math.floor(idx / 2);
  }
  return { pathElements, pathIndices, root: levels[DEPTH][0] };
}

// ── CLI commands ──────────────────────────────────────────────────────────────

async function cmdAdd(secret) {
  const poseidon = await getPoseidon();
  const state    = loadState();
  const secretBig = BigInt(secret);

  if (state.secrets.some(s => s === secretBig)) {
    console.error("Error: secret already in tree");
    process.exit(1);
  }

  // Find next empty slot
  const nextIndex = state.secrets.length;
  if (nextIndex >= TREE_SIZE) {
    console.error(`Error: tree is full (max ${TREE_SIZE} members)`);
    process.exit(1);
  }

  const leaf = poseidon.hash1(secretBig);
  state.leaves[nextIndex] = leaf;
  state.secrets.push(secretBig);
  saveState(state);

  const root = await getRoot(state.leaves, poseidon);
  console.log(JSON.stringify({
    index: nextIndex,
    leaf:  leaf.toString(),
    root:  root.toString(),
  }, null, 2));
}

async function cmdRoot() {
  const poseidon = await getPoseidon();
  const state    = loadState();
  const root     = await getRoot(state.leaves, poseidon);
  console.log(root.toString());
}

async function cmdProof(secret) {
  const poseidon  = await getPoseidon();
  const state     = loadState();
  const secretBig = BigInt(secret);
  const index     = state.secrets.findIndex(s => s === secretBig);

  if (index === -1) {
    console.error("Error: secret not found in tree");
    process.exit(1);
  }

  const { pathElements, pathIndices, root } = await getMerkleProof(
    state.leaves, index, poseidon
  );

  console.log(JSON.stringify({
    index,
    root:         root.toString(),
    pathElements: pathElements.map(String),
    pathIndices:  pathIndices.map(String),
  }, null, 2));
}

async function cmdInput(secret, proposalId, voteYes) {
  const poseidon  = await getPoseidon();
  const state     = loadState();
  const secretBig = BigInt(secret);
  const index     = state.secrets.findIndex(s => s === secretBig);

  if (index === -1) {
    console.error("Error: secret not found in tree. Run: node scripts/tree.js add <secret>");
    process.exit(1);
  }

  const { pathElements, pathIndices, root } = await getMerkleProof(
    state.leaves, index, poseidon
  );
  const nullifierHash = poseidon.hash2(secretBig, BigInt(proposalId));

  const input = {
    // private
    secret:       secretBig.toString(),
    pathElements: pathElements.map(String),
    pathIndices:  pathIndices.map(String),
    // public
    nullifierHash: nullifierHash.toString(),
    proposalId:    BigInt(proposalId).toString(),
    voteYes:       voteYes === "1" ? "1" : "0",
    membershipRoot: root.toString(),
  };

  console.log(JSON.stringify(input, null, 2));
}

async function cmdVerify(secret) {
  const poseidon  = await getPoseidon();
  const state     = loadState();
  const secretBig = BigInt(secret);
  const index     = state.secrets.findIndex(s => s === secretBig);

  if (index === -1) {
    console.log("NOT IN TREE");
    process.exit(1);
  }

  const root = await getRoot(state.leaves, poseidon);
  console.log(JSON.stringify({
    member: true,
    index,
    root: root.toString(),
  }, null, 2));
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
})().catch(err => { console.error(err); process.exit(1); });
