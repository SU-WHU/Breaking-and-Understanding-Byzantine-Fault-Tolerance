function minimumQuorum(totalNodes) {
    if (!Number.isSafeInteger(totalNodes) || totalNodes < 1) {
        throw new Error("Invalid validator count");
    }
    return Math.floor((2 * totalNodes) / 3) + 1;
}

function validateQuorum(totalNodes, quorumSize) {
    const minimum = minimumQuorum(totalNodes);
    if (!Number.isSafeInteger(quorumSize) ||
        quorumSize < minimum || quorumSize > totalNodes) {
        throw new Error(
            `Unsafe quorum size: ${quorumSize}; expected ${minimum} to ${totalNodes}`
        );
    }
    return quorumSize;
}

class QuorumEngine {
    constructor(totalNodes) { this.totalNodes = totalNodes; }
    size() { return minimumQuorum(this.totalNodes); }
    reached(voteCount) { return voteCount >= this.size(); }
}

module.exports = QuorumEngine;
module.exports.minimumQuorum = minimumQuorum;
module.exports.validateQuorum = validateQuorum;
