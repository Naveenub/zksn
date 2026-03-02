# ZKSN DAO Governance

## Design Philosophy

ZKSN governance has **no administrators, no multisig, no named signers**.

All protocol changes require:
1. A public proposal (IPFS-stored, hash on-chain)
2. Anonymous community voting via ZK-SNARK membership proofs
3. A 2-day time lock before execution

This means: **no single entity can unilaterally change the protocol**.

---

## How It Works

### Membership Credentials

Membership in the ZKSN DAO is represented by a ZK credential — not an Ethereum address. This means:

- You can vote without revealing your wallet address
- You can vote without revealing your ZKSN node identity  
- The only thing the contract learns is that "some valid member voted"

Credentials are issued by the network when a node has:
- Operated for a minimum period
- Forwarded a minimum volume of packets
- Maintained uptime above a threshold

### Voting Flow

```
1. Member generates ZK proof:
   proof = ZkSnark.prove(
     private_inputs: [credential, nullifier_secret],
     public_inputs:  [proposalId, voteChoice, membershipRoot]
   )

2. Member calls:
   governance.vote(proposalId, support, nullifierHash, proof)

3. Contract verifies:
   - ZK proof is valid
   - Membership root matches
   - Nullifier not previously used

4. Vote is counted anonymously.
```

### Proposal Flow

```
Anyone → propose(contentHash, target, payload)
Community → vote() for 7 days
Anyone → finalize() after voting ends
  → if passed: 2-day time lock begins
Anyone → execute() after time lock
  → proposal executes autonomously
```

---

## Development Setup

### Prerequisites

```bash
# Install Foundry (Solidity toolchain)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
cd governance
forge install
```

### Compile

```bash
forge build
```

### Test

```bash
forge test -vvv
```

### Deploy (testnet)

```bash
# Set environment variables
export PRIVATE_KEY=<deployer_key>
export RPC_URL=<testnet_rpc>

forge script scripts/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast
```

---

## ZK Circuit

The membership voting circuit is not included in this scaffold (it requires a trusted setup or a transparent setup like Groth16 or PLONK).

Recommended tools:
- **Circom** + **snarkjs** for circuit development
- **Noir** (Aztec) for a Rust-friendly ZK DSL
- **Halo2** for transparent setup (no trusted ceremony)

The circuit must prove:
1. `credential` is a leaf in the Merkle tree with root `membershipRoot`
2. `nullifierHash = Poseidon(credential, proposalId)`
3. `support` matches the committed vote value

See `contracts/IVerifier.sol` for the interface the contract expects.
