const Network = require("./network");
const QuorumEngine = require("./quorum");
const { validateQuorum } = require("./quorum");
const ValidatorRegistry = require("./registry");
const EvidenceLog = require("./evidence");
const { buildCertificate, verifyCertificate } = require("./certificate");

class Simulator {
    constructor(nodes, customQuorumEngine = null, options = {}) {
        this.nodes = nodes;
        this.network = new Network();
        // Initial membership is trusted configuration. Supply an independent
        // registry when the participant list may include attackers.
        this.registry = options.registry || new ValidatorRegistry(nodes);
        this.quorum = customQuorumEngine || new QuorumEngine(this.registry.size);
        this.evidence = new EvidenceLog();
        this.auditLog = [];
        this.certificates = [];
        this.lastRound = 0;
        this.quiet = options.quiet || false;
    }

    log(...args) {
        if (!this.quiet) console.log(...args);
    }

    validatedQuorum() {
        return validateQuorum(this.registry.size, this.quorum.size());
    }

    runConsensus(value, roundId = this.lastRound + 1) {
        this.validatedQuorum();
        const deliveries = this.nodes.map(node => ({
            vote: node.vote(value, roundId), recipient: "consensus"
        }));
        return this.runVotes(value, deliveries, roundId);
    }

    runVotes(proposal, deliveries, roundId = this.lastRound + 1) {
        if (!Number.isSafeInteger(roundId) || roundId <= this.lastRound) {
            throw new Error("Round must be a positive, strictly increasing integer");
        }
        const quorum = this.validatedQuorum();
        this.lastRound = roundId;
        const accepted = new Map();
        const rejected = [];
        const conflictStart = this.evidence.conflicts.length;
        this.log(`\nRound ${roundId}; proposal ${proposal}; required quorum ${quorum}`);

        // Process the complete supplied batch before making a decision.
        for (const delivery of deliveries) {
            const vote = delivery && delivery.vote;
            const recipient = delivery && delivery.recipient;
            const check = this.registry.checkVote(vote, roundId);
            if (!check.ok) {
                rejected.push({ nodeId: vote && vote.nodeId, reason: check.reason });
                this.log(`REJECTED ${vote && vote.nodeId}: ${check.reason}`);
                continue;
            }
            const state = this.evidence.observe(vote, recipient);
            if (state === "equivocation") {
                accepted.delete(vote.nodeId);
                rejected.push({ nodeId: vote.nodeId, reason: "Equivocation" });
                this.log(`EQUIVOCATION DETECTED: ${vote.nodeId} in round ${roundId}`);
            } else if (state === "duplicate") {
                rejected.push({ nodeId: vote.nodeId, reason: "Duplicate vote" });
                this.log(`REJECTED ${vote.nodeId}: Duplicate vote`);
            } else {
                accepted.set(vote.nodeId, { ...vote });
                this.log(`${vote.nodeId} voted ${vote.value}`);
            }
        }

        const groups = new Map();
        for (const vote of accepted.values()) {
            if (!groups.has(vote.value)) groups.set(vote.value, []);
            groups.get(vote.value).push(vote);
        }
        const tally = [...groups].map(([value, votes]) => ({ value, votes: votes.length }));
        // A custom reached() method cannot bypass the checked threshold.
        const winners = tally.filter(candidate => candidate.votes >= quorum);
        if (winners.length > 1) throw new Error("Conflicting quorum invariant");
        let certificate = null;
        if (winners.length === 1) {
            const value = winners[0].value;
            certificate = buildCertificate(roundId, value, groups.get(value), quorum);
            const verified = verifyCertificate(certificate, this.registry, quorum);
            if (!verified.valid) throw new Error(verified.reason);
            this.certificates.push(structuredClone(certificate));
            this.log(`COMMITTED: ${value}`);
            this.log(`COMMIT CERTIFICATE: signed by ${verified.signers.join(", ")}`);
        } else {
            this.log("NO CONSENSUS");
        }
        const result = {
            roundId, proposal, quorum, votes: [...accepted.values()], tally, winners,
            rejected, equivocations: this.evidence.conflicts.slice(conflictStart),
            certificate, status: certificate ? "COMMITTED" : "NO CONSENSUS"
        };
        this.auditLog.push(structuredClone(result));
        return result;
    }
}

module.exports = Simulator;
