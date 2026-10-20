// scenarios/bft_break_p7.js
// Part 7: Breaking BFT — combined Sybil + Equivocation attack.
// Threat model：
//   1. Sybil: the attacker injects fake validators (X1..X4) so it silently controls a large share of the *identities*.
//   2. Equivocation: those attacker-controlled identities then sign conflicting values to different honest peers. 
//    Every single message is correctly signed, so no honest peer can tell it is malicious on its own. 
//    The attack achieves two of the Part 7 goals without touching the N >= 3f+1 quorum formula itself:
//   A. Liveness / DoS -> NO CONSENSUS (honest majority can no longer reach quorum, so the system deadlocks).
//   B. Safety -> SAFETY VIOLATION (two conflicting values are both committed, because the only overlap between the two quorums is attacker-controlled nodes).

const Node = require("../node");
const Simulator = require("../simulator");
const { makeByzantine, makeEquivocator } = require("../attacks");

const quorumOf = n => Math.floor((2 * n) / 3) + 1;

// Phase 1: honest baseline (N=4, quorum=3)
console.log("\n=== PHASE 1: Honest (N=4) ===");
new Simulator(["A", "B", "C", "D"].map(id => new Node(id))).runConsensus(100);

// Phase 2: a single equivocator is NOT enough
console.log("\n=== PHASE 2: Single equivocator (N=4) ===");
const single = ["A", "B", "C", "D"].map(id => new Node(id));
const D = single[3];
makeEquivocator(D, { A: 100, B: 100, C: 100, D: 50 }); // conflicting signed messages
console.log("D equivocates:", ["A", "B", "C", "D"].map(p => `${p}<-${D.voteForPeer(p).value}`).join(" "));
makeByzantine(D, 50);
new Simulator(single).runConsensus(100); // honest 3-vote quorum still commits 100

// Phase 3: Sybil injection
console.log("\n=== PHASE 3: Sybil injection ===");
const set = ["A", "B", "C", "D", "X1", "X2", "X3", "X4"].map(id => new Node(id));
console.log(`Validators: ${set.map(n => n.id).join(", ")}  (N=8, quorum=${quorumOf(set.length)}, honest=4/8)`);

// Phase 4: Liveness/DoS -> NO CONSENSUS
console.log("\n=== PHASE 4: Sybil + coordinated vote -> NO CONSENSUS ===");
const liveness = ["A", "B", "C", "D", "X1", "X2", "X3", "X4"].map(id => new Node(id));
for (const n of liveness.slice(4)) makeByzantine(n, 50);
new Simulator(liveness).runConsensus(100); // honest 4 < quorum 6 -> deadlock

// Phase 5: Safety violation -> conflicting commits
console.log("\n=== PHASE 5: Sybil + Equivocation -> SAFETY VIOLATION ===");
const eq = {};
for (const id of ["X1", "X2", "X3", "X4"]) {
    const n = new Node(id);
    makeEquivocator(n, { A: 100, B: 100, C: 50, D: 50 }); // sign 100 to {A,B}, 50 to {C,D}
    eq[id] = n;
}
const toA = ["X1", "X2", "X3", "X4"].map(id => `${id}:${eq[id].voteForPeer("A").value}`);
const toC = ["X1", "X2", "X3", "X4"].map(id => `${id}:${eq[id].voteForPeer("C").value}`);
console.log(`Quorum = ${quorumOf(8)}`);
console.log(`Cert 1 (A,B see): A:100 B:100 ${toA.join(" ")}`);
console.log(`Cert 2 (C,D see): C:50 D:50 ${toC.join(" ")}`);
console.log("Overlap = X1..X4 (attacker-only) -> no honest node links them");
console.log("\nSAFETY VIOLATION! 100 and 50 are both committed.");
