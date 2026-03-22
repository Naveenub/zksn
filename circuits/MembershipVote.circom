pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

template MerkleProof(depth) {
    signal input  leaf;
    signal input  pathElements[depth];
    signal input  pathIndices[depth];
    signal output root;

    component hashers[depth];
    component leftMux[depth];
    component rightMux[depth];
    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // left input:  if pathIndices[i]==0 → current node, else sibling
        leftMux[i] = Mux1();
        leftMux[i].c[0] <== levelHashes[i];
        leftMux[i].c[1] <== pathElements[i];
        leftMux[i].s    <== pathIndices[i];

        // right input: if pathIndices[i]==0 → sibling, else current node
        rightMux[i] = Mux1();
        rightMux[i].c[0] <== pathElements[i];
        rightMux[i].c[1] <== levelHashes[i];
        rightMux[i].s    <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== leftMux[i].out;
        hashers[i].inputs[1] <== rightMux[i].out;

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[depth];
}

template MembershipVote(depth) {
    signal input secret;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    signal input nullifierHash;
    signal input proposalId;
    signal input voteYes;
    signal input membershipRoot;

    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== secret;
    signal leaf <== leafHasher.out;

    component merkle = MerkleProof(depth);
    merkle.leaf          <== leaf;
    merkle.pathElements  <== pathElements;
    merkle.pathIndices   <== pathIndices;
    merkle.root === membershipRoot;

    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== proposalId;
    nullifierHasher.out === nullifierHash;

    signal voteCheck;
    voteCheck <== voteYes * (1 - voteYes);
    voteCheck === 0;
}

component main {public [nullifierHash, proposalId, voteYes, membershipRoot]} =
    MembershipVote(20);
