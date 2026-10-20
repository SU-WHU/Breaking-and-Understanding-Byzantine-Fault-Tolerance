const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Node = require("../node");
const Simulator = require("../simulator");
const ValidatorRegistry = require("../registry");
const { verifyCertificate } = require("../certificate");
const { makeEquivocator, makeByzantine, stealKey, forgeVote } = require("../attacks");

function nodes() { return ["A", "B", "C", "D"].map(id => new Node(id)); }
function deliver(vote, recipient = "consensus") { return { vote, recipient }; }
function heading(text) { console.log(`\n${text}`); }

function equivocation() {
    heading("Task 8.1: Detect equivocation");
    const members = nodes();
    const d = members[3];
    makeEquivocator(d, { A: 100, B: 50, C: 75 });
    const simulator = new Simulator(members);
    const deliveries = [
        ...members.slice(0, 3).map(node => deliver(node.vote(100))),
        ...["A", "B", "C"].map(peer => deliver(d.voteForPeer(peer), peer))
    ];
    const result = simulator.runVotes(100, deliveries, 1);
    assert.equal(result.equivocations.length, 1);
    assert.deepEqual(result.certificate.signatures.map(vote => vote.nodeId), ["A", "B", "C"]);
    assert.equal(result.equivocations[0].messages[0].recipient, "A");
    assert.equal(result.equivocations[0].messages[1].recipient, "B");
    return { task: "8.1", result, trustedValidators: simulator.registry.snapshot() };
}

function keyProtection() {
    heading("Task 8.2: Rotate keys and revoke a validator");
    const members = nodes();
    const registry = new ValidatorRegistry(members);
    const simulator = new Simulator(members, null, { registry });
    const stolen = stealKey(members[0]);
    const forged = forgeVote("A", stolen, 999);
    const beforeRotation = registry.checkVote(forged, 1);
    assert.equal(beforeRotation.ok, true);
    console.log("Before rotation: the stolen current key passes verification.");

    registry.updateKey(members[0].rotateKey());
    const rotation = simulator.runVotes(100, [
        deliver(forged),
        // An attacker cannot rescue the stolen key by changing its version.
        deliver(forgeVote("A", stolen, 999, 1, 2)),
        ...members.map(node => deliver(node.vote(100, 1)))
    ], 1);
    assert.deepEqual(rotation.rejected.map(item => item.reason), [
        "Obsolete key version", "Invalid signature"
    ]);
    assert.equal(rotation.certificate.value, 100);

    registry.revoke("A");
    const revocation = simulator.runConsensus(100, 2);
    assert.equal(revocation.rejected[0].reason, "Revoked validator");
    assert.deepEqual(revocation.certificate.signatures.map(vote => vote.nodeId), ["B", "C", "D"]);
    assert.equal(revocation.quorum, 3);
    return { task: "8.2", beforeRotation, rotation, revocation };
}

function sybil() {
    heading("Task 8.3: Enforce approved membership");
    const members = nodes();
    // Capture the approved set before the attacker supplies any identities.
    const registry = new ValidatorRegistry(members);
    const fake = ["X1", "X2", "X3", "X4"].map(id => new Node(id));
    fake.forEach(node => makeByzantine(node, 999));
    const impersonator = new Node("A");
    makeByzantine(impersonator, 999);
    const simulator = new Simulator([...members, ...fake, impersonator], null, { registry });
    const result = simulator.runConsensus(100);
    assert.equal(result.rejected.filter(item => item.reason === "Unapproved validator").length, 4);
    assert.equal(result.rejected.filter(item => item.reason === "Invalid signature").length, 1);
    assert.equal(result.quorum, 3);
    assert.equal(result.certificate.value, 100);
    return { task: "8.3", approved: registry.snapshot().map(entry => entry.id), result };
}

function quorum() {
    heading("Task 8.4: Protect quorum rules");
    const members = nodes();
    makeByzantine(members[2], 50);
    makeByzantine(members[3], 50);
    const weak = { size: () => 2, reached: count => count >= 2 };
    const reference = { quorum: 2, tally: [{ value: 100, votes: 2 }, { value: 50, votes: 2 }] };
    console.log("Unprotected reference: both 100 and 50 have two votes and meet a quorum of 2.");
    let blocked;
    try {
        new Simulator(members, weak).runConsensus(100);
    } catch (error) {
        blocked = error.message;
        console.log(`BLOCKED: ${blocked}`);
    }
    assert.match(blocked, /Unsafe quorum size/);
    const split = new Simulator(members).runConsensus(100);
    assert.equal(split.status, "NO CONSENSUS");
    const honest = new Simulator(nodes()).runConsensus(100);
    assert.equal(honest.status, "COMMITTED");
    return { task: "8.4", reference, blocked, split, honest };
}

function certificates() {
    heading("Task 8.5: Build and verify a commit certificate");
    const members = nodes();
    makeByzantine(members[3], 50);
    const simulator = new Simulator(members);
    const result = simulator.runConsensus(100);
    const verification = verifyCertificate(result.certificate, simulator.registry, 3);
    assert.equal(verification.valid, true);
    const tampered = structuredClone(result.certificate);
    tampered.value = 999;
    const tamperCheck = verifyCertificate(tampered, simulator.registry, 3);
    assert.equal(tamperCheck.valid, false);
    console.log(`Certificate verified: ${verification.signers.join(", ")}`);
    console.log(`Tampered certificate rejected: ${tamperCheck.reason}`);
    return {
        task: "8.5", result, verification, tamperCheck,
        trustedValidators: simulator.registry.snapshot()
    };
}

function main() {
    const results = [equivocation(), keyProtection(), sybil(), quorum(), certificates()];
    const directory = path.join(__dirname, "..", "evidence");
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, "part8-results.json"), JSON.stringify({
        generatedAt: new Date().toISOString(), nodeVersion: process.version, results
    }, null, 2) + "\n");
    const last = results[4];
    fs.writeFileSync(path.join(directory, "commit-certificate.json"),
        JSON.stringify(last.result.certificate, null, 2) + "\n");
    fs.writeFileSync(path.join(directory, "trusted-config.json"), JSON.stringify({
        quorum: 3, validators: last.trustedValidators
    }, null, 2) + "\n");
    console.log("\nAll five Part 8 demonstrations passed. Evidence saved in evidence/.");
}

if (require.main === module) main();
module.exports = { equivocation, keyProtection, sybil, quorum, certificates };
