const { createPublicKey } = require("node:crypto");
const { validVoteShape, verifyVote } = require("./crypto");

class ValidatorRegistry {
    constructor(approvedValidators) {
        this.validators = new Map();
        for (const validator of approvedValidators) {
            const entry = validator.publicInfo || validator;
            if (this.validators.has(entry.id)) {
                throw new Error(`Duplicate validator: ${entry.id}`);
            }
            this.validateEntry(entry);
            this.validators.set(entry.id, { ...entry, revoked: !!entry.revoked });
        }
        if (this.validators.size === 0) throw new Error("Empty validator registry");
    }

    validateEntry(entry) {
        if (typeof entry.id !== "string" || !entry.id ||
            !Number.isSafeInteger(entry.keyVersion) || entry.keyVersion < 1 ||
            typeof entry.publicKey !== "string" ||
            createPublicKey(entry.publicKey).asymmetricKeyType !== "ed25519") {
            throw new Error("Invalid validator registration");
        }
    }

    get size() {
        // Revocation blocks votes without silently shrinking the electorate.
        return this.validators.size;
    }

    snapshot() {
        return [...this.validators.values()].map(entry => ({ ...entry }));
    }

    updateKey(publicInfo) {
        const previous = this.validators.get(publicInfo.id);
        if (!previous || previous.revoked) {
            throw new Error("Cannot update an unknown or revoked validator");
        }
        this.validateEntry(publicInfo);
        if (publicInfo.keyVersion !== previous.keyVersion + 1 ||
            publicInfo.publicKey === previous.publicKey) {
            throw new Error("Key rotation requires a new key and the next version");
        }
        // Administrative operation; never driven by incoming votes.
        this.validators.set(publicInfo.id, { ...publicInfo, revoked: false });
    }

    revoke(id) {
        const entry = this.validators.get(id);
        if (!entry) throw new Error(`Unknown validator: ${id}`);
        entry.revoked = true;
    }

    checkVote(vote, expectedRound) {
        if (!validVoteShape(vote)) return { ok: false, reason: "Malformed vote" };
        const entry = this.validators.get(vote.nodeId);
        if (!entry) return { ok: false, reason: "Unapproved validator" };
        if (entry.revoked) return { ok: false, reason: "Revoked validator" };
        if (vote.roundId !== expectedRound) return { ok: false, reason: "Wrong round" };
        if (vote.keyVersion !== entry.keyVersion) {
            return { ok: false, reason: "Obsolete key version" };
        }
        if (!verifyVote(vote, entry.publicKey)) {
            return { ok: false, reason: "Invalid signature" };
        }
        return { ok: true };
    }
}

module.exports = ValidatorRegistry;
