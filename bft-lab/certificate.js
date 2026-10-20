const { validateQuorum } = require("./quorum");

function buildCertificate(roundId, value, votes, quorum) {
    return {
        protocol: "bft-lab-v1", roundId, value, quorum,
        signatures: votes.map(vote => ({ ...vote }))
    };
}

function verifyCertificate(certificate, registry, expectedQuorum) {
    try {
        if (!certificate || certificate.protocol !== "bft-lab-v1" ||
            !Array.isArray(certificate.signatures)) {
            throw new Error("Malformed certificate");
        }
        // The registry and threshold come from trusted configuration.
        validateQuorum(registry.size, expectedQuorum);
        if (certificate.quorum !== expectedQuorum) {
            throw new Error("Certificate quorum does not match trusted policy");
        }
        const signers = new Set();
        for (const vote of certificate.signatures) {
            const check = registry.checkVote(vote, certificate.roundId);
            if (!check.ok) throw new Error(check.reason);
            if (vote.value !== certificate.value) throw new Error("Value mismatch");
            if (signers.has(vote.nodeId)) throw new Error("Duplicate signer");
            signers.add(vote.nodeId);
        }
        if (signers.size < expectedQuorum) throw new Error("Insufficient signatures");
        return { valid: true, signers: [...signers] };
    } catch (error) {
        return { valid: false, reason: error.message };
    }
}

module.exports = { buildCertificate, verifyCertificate };
