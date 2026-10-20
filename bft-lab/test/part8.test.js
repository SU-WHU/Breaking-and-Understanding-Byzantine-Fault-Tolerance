const test = require("node:test");
const assert = require("node:assert/strict");
const Node = require("../node");
const Simulator = require("../simulator");
const Registry = require("../registry");
const { verifyCertificate } = require("../certificate");
const { minimumQuorum } = require("../quorum");
const { forgeVote, makeByzantine } = require("../attacks");

function fixture(customQuorum = null) {
    const nodes = ["A", "B", "C", "D"].map(id => new Node(id));
    const registry = new Registry(nodes);
    const sim = new Simulator(nodes, customQuorum, { registry, quiet: true });
    return { nodes, registry, sim };
}
function delivery(vote, recipient = "consensus") { return { vote, recipient }; }
function ballots(nodes, value = 100, roundId = 1) {
    return nodes.map(node => delivery(node.vote(value, roundId)));
}

test("Honest validators commit a verifiable certificate", () => {
    const { sim, registry } = fixture();
    const result = sim.runConsensus(100);
    assert.equal(result.certificate.value, 100);
    assert.equal(result.quorum, 3);
    assert.equal(verifyCertificate(result.certificate, registry, 3).valid, true);
});

test("Three honest votes tolerate one conflicting Byzantine vote", () => {
    const { sim, nodes } = fixture();
    makeByzantine(nodes[3], 50);
    const result = sim.runConsensus(100);
    assert.deepEqual(result.certificate.signatures.map(vote => vote.nodeId), ["A", "B", "C"]);
});

test("8.1: conflicting signed evidence removes an earlier accepted vote", () => {
    const { nodes, sim, registry } = fixture();
    const result = sim.runVotes(100, [
        delivery(nodes[3].vote(100), "A"),
        ...ballots(nodes.slice(0, 3)),
        delivery(nodes[3].vote(50), "B"),
        delivery(nodes[3].vote(100), "C")
    ]);
    assert.equal(result.equivocations.length, 1);
    assert.equal(result.votes.length, 3);
    assert.equal(result.certificate.signatures.some(vote => vote.nodeId === "D"), false);
    for (const vote of result.equivocations[0].messages) {
        assert.equal(registry.checkVote(vote, 1).ok, true);
    }
});

test("8.1: equivocation cannot supply a third vote to two honest validators", () => {
    const { nodes, sim } = fixture();
    const result = sim.runVotes(100, [
        ...ballots(nodes.slice(0, 2)),
        delivery(nodes[3].vote(100)), delivery(nodes[3].vote(50))
    ]);
    assert.equal(result.status, "NO CONSENSUS");
});

test("8.1: the same value sent to several recipients counts once", () => {
    const { nodes, sim } = fixture();
    const result = sim.runVotes(100, [
        delivery(nodes[0].vote(100), "B"),
        delivery(nodes[0].vote(100), "C"),
        delivery(nodes[0].vote(100), "D")
    ]);
    assert.equal(result.votes.length, 1);
    assert.equal(result.equivocations.length, 0);
    assert.equal(result.status, "NO CONSENSUS");
});

test("8.1: different values in different rounds are not equivocation", () => {
    const { sim } = fixture();
    sim.runConsensus(100, 1);
    const result = sim.runConsensus(50, 2);
    assert.equal(result.equivocations.length, 0);
    assert.equal(result.certificate.value, 50);
});

test("8.1: an invalid conflicting signature cannot frame a validator", () => {
    const { nodes, sim } = fixture();
    const result = sim.runVotes(100, [
        ...ballots(nodes), delivery({ ...nodes[0].vote(100), value: 50 })
    ]);
    assert.equal(result.equivocations.length, 0);
    assert.equal(result.votes.length, 4);
    assert.equal(result.rejected[0].reason, "Invalid signature");
});

test("8.2: a stolen current key verifies before rotation", () => {
    const { nodes, registry } = fixture();
    assert.equal(registry.checkVote(forgeVote("A", nodes[0].secret, 999), 1).ok, true);
});

test("8.2: rotation rejects both obsolete and relabelled stolen-key votes", () => {
    const { nodes, registry, sim } = fixture();
    const stolen = nodes[0].secret;
    registry.updateKey(nodes[0].rotateKey());
    const result = sim.runVotes(100, [
        delivery(forgeVote("A", stolen, 999)),
        delivery(forgeVote("A", stolen, 999, 1, 2)),
        ...ballots(nodes)
    ]);
    assert.deepEqual(result.rejected.map(item => item.reason), [
        "Obsolete key version", "Invalid signature"
    ]);
    assert.equal(result.votes.length, 4);
});

test("8.2: rotating a node requires an explicit trusted registry update", () => {
    const { nodes, registry } = fixture();
    nodes[0].rotateKey();
    assert.equal(registry.checkVote(nodes[0].vote(100), 1).ok, false);
    registry.updateKey(nodes[0].publicInfo);
    assert.equal(registry.checkVote(nodes[0].vote(100), 1).ok, true);
});

test("8.2: key versions cannot be rolled back", () => {
    const { nodes, registry } = fixture();
    const old = nodes[0].publicInfo;
    registry.updateKey(nodes[0].rotateKey());
    assert.throws(() => registry.updateKey(old), /next version/);
});

test("8.2: revoked validators cannot vote or silently re-register", () => {
    const { nodes, registry, sim } = fixture();
    registry.revoke("A");
    assert.throws(() => registry.updateKey(nodes[0].rotateKey()), /revoked/);
    const result = sim.runConsensus(100);
    assert.equal(result.rejected[0].reason, "Revoked validator");
    assert.equal(result.quorum, 3);
    assert.equal(result.certificate.signatures.length, 3);
});

test("8.2: two revocations stop progress without lowering quorum", () => {
    const { registry, sim } = fixture();
    registry.revoke("A");
    registry.revoke("B");
    const result = sim.runConsensus(100);
    assert.equal(registry.size, 4);
    assert.equal(result.quorum, 3);
    assert.equal(result.status, "NO CONSENSUS");
});

test("8.3: four attacker identities gain no voting power", () => {
    const { nodes, sim, registry } = fixture();
    sim.nodes.push(...["X1", "X2", "X3", "X4"].map(id => new Node(id)));
    const result = sim.runConsensus(100);
    assert.equal(result.rejected.length, 4);
    assert.equal(result.votes.length, 4);
    assert.equal(registry.size, 4);
    assert.equal(result.quorum, 3);
    assert.equal(nodes.length, 8);
});

test("8.3: copying an approved name without its key fails authentication", () => {
    const { nodes, sim } = fixture();
    const impostor = new Node("A");
    const result = sim.runVotes(100, [
        delivery(impostor.vote(999)), ...ballots(nodes)
    ]);
    assert.equal(result.rejected[0].reason, "Invalid signature");
    assert.equal(result.certificate.value, 100);
});

test("8.3: duplicate registrations are rejected", () => {
    const a = new Node("A");
    assert.throws(() => new Registry([a, a]), /Duplicate validator/);
});

test("8.3: repeated authenticated votes cannot manufacture a quorum", () => {
    const { nodes, sim } = fixture();
    const vote = nodes[0].vote(100);
    const result = sim.runVotes(100, Array.from({ length: 20 }, () => delivery(vote)));
    assert.equal(result.votes.length, 1);
    assert.equal(result.status, "NO CONSENSUS");
});

for (const size of [0, 2, 2.5, NaN, Infinity, 5]) {
    test(`8.4: reject unsafe or invalid quorum ${size}`, () => {
        const { sim } = fixture({ size: () => size });
        assert.throws(() => sim.runConsensus(100), /Unsafe quorum size/);
    });
}

test("8.4: correct thresholds for four and seven approved validators", () => {
    assert.equal(minimumQuorum(4), 3);
    assert.equal(minimumQuorum(7), 5);
});

test("8.4: a split vote cannot commit under a valid quorum", () => {
    const { nodes, sim } = fixture();
    makeByzantine(nodes[2], 50);
    makeByzantine(nodes[3], 50);
    assert.equal(sim.runConsensus(100).status, "NO CONSENSUS");
});

test("8.4: a dishonest reached() implementation cannot bypass the threshold", () => {
    const { nodes, sim } = fixture({ size: () => 3, reached: () => true });
    const result = sim.runVotes(100, ballots(nodes.slice(0, 2)));
    assert.equal(result.status, "NO CONSENSUS");
});

test("8.4: quorum changes are rechecked before every round", () => {
    let size = 3;
    const { sim } = fixture({ size: () => size });
    sim.runConsensus(100);
    size = 2;
    assert.throws(() => sim.runConsensus(100), /Unsafe quorum size/);
});

const certificateMutations = {
    "altered value": certificate => { certificate.value = 999; },
    "altered round": certificate => { certificate.roundId = 2; },
    "altered signature": certificate => { certificate.signatures[0].signature = "invalid"; },
    "duplicate signers": certificate => {
        certificate.signatures = Array(3).fill(certificate.signatures[0]);
    },
    "insufficient signatures": certificate => { certificate.signatures.length = 2; },
    "weakened quorum metadata": certificate => { certificate.quorum = 2; },
    "unapproved signer": certificate => {
        certificate.signatures[0] = new Node("X").vote(100);
    }
};
for (const [name, mutate] of Object.entries(certificateMutations)) {
    test(`8.5: reject a certificate with ${name}`, () => {
        const { sim, registry } = fixture();
        const certificate = sim.runConsensus(100).certificate;
        mutate(certificate);
        assert.equal(verifyCertificate(certificate, registry, 3).valid, false);
    });
}

test("8.5: certificate signatures contain only votes for the committed value", () => {
    const { nodes, sim } = fixture();
    makeByzantine(nodes[3], 50);
    const certificate = sim.runConsensus(100).certificate;
    assert.equal(certificate.signatures.length, 3);
    assert.ok(certificate.signatures.every(vote => vote.value === 100));
});

test("8.5: certificate must satisfy the verifier's stricter quorum policy", () => {
    const { sim, registry } = fixture();
    const certificate = sim.runConsensus(100).certificate;
    assert.equal(verifyCertificate(certificate, registry, 4).valid, false);
});

test("8.5: exported public configuration independently verifies saved evidence", () => {
    const { sim, registry } = fixture();
    const certificate = JSON.parse(JSON.stringify(sim.runConsensus(100).certificate));
    const publicRegistry = new Registry(JSON.parse(JSON.stringify(registry.snapshot())));
    assert.equal(verifyCertificate(certificate, publicRegistry, 3).valid, true);
    assert.equal(JSON.stringify(publicRegistry.snapshot()).includes("PRIVATE KEY"), false);
});

test("8.5: modifying returned evidence does not rewrite the stored audit record", () => {
    const { sim } = fixture();
    const result = sim.runConsensus(100);
    result.certificate.value = 999;
    result.votes[0].value = 999;
    assert.equal(sim.certificates[0].value, 100);
    assert.equal(sim.auditLog[0].votes[0].value, 100);
});

test("Rounds reject old messages and signed-field tampering", () => {
    const { nodes, sim } = fixture();
    const old = nodes[0].vote(100, 1);
    sim.runConsensus(100, 1);
    const result = sim.runVotes(100, [
        delivery(old), delivery({ ...old, roundId: 2 }),
        ...ballots(nodes, 100, 2)
    ], 2);
    assert.deepEqual(result.rejected.map(item => item.reason), [
        "Wrong round", "Invalid signature"
    ]);
    assert.equal(result.certificate.value, 100);
});

test("A completed round cannot be reused for a conflicting local commit", () => {
    const { sim } = fixture();
    sim.runConsensus(100, 1);
    assert.throws(() => sim.runConsensus(50, 1), /strictly increasing/);
});

test("Malformed and unsigned votes are rejected without stopping honest votes", () => {
    const { nodes, sim } = fixture();
    const result = sim.runVotes(100, [
        delivery(null), delivery({ nodeId: "A", value: 100 }),
        delivery({ ...nodes[0].vote(100), signature: "" }),
        ...ballots(nodes)
    ]);
    assert.equal(result.rejected.length, 3);
    assert.equal(result.status, "COMMITTED");
});

test("Numeric and textual values remain distinct during tallying", () => {
    const { nodes, sim } = fixture();
    const result = sim.runVotes(100, [
        ...ballots(nodes.slice(0, 2), 100),
        ...ballots(nodes.slice(2), "100")
    ]);
    assert.equal(result.tally.length, 2);
    assert.equal(result.status, "NO CONSENSUS");
});
