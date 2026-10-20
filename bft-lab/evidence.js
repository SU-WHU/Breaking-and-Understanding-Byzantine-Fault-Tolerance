class EvidenceLog {
    constructor() {
        this.rounds = new Map();
        this.conflicts = [];
    }

    observe(vote, recipient) {
        // Call only after membership, round and signature validation.
        if (!this.rounds.has(vote.roundId)) {
            this.rounds.set(vote.roundId, new Map());
        }
        const round = this.rounds.get(vote.roundId);
        const message = { ...vote, recipient };
        const existing = round.get(vote.nodeId);
        if (!existing) {
            round.set(vote.nodeId, { first: message, conflicted: false });
            return "accepted";
        }
        if (existing.first.value !== vote.value) {
            if (!existing.conflicted) {
                this.conflicts.push({
                    nodeId: vote.nodeId,
                    roundId: vote.roundId,
                    messages: [{ ...existing.first }, message]
                });
            }
            existing.conflicted = true;
            return "equivocation";
        }
        return existing.conflicted ? "equivocation" : "duplicate";
    }
}

module.exports = EvidenceLog;
