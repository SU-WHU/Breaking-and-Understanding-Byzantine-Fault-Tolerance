const Node = require("./node");
const { sign } = require("./crypto");

function resetNode(node) {
    node.vote = Node.prototype.vote;
}

function makeByzantine(node, maliciousValue) {
    node.vote = function (_, roundId = 1) {
        return Node.prototype.vote.call(this, maliciousValue, roundId);
    };
}

function makeEquivocator(node, valuesPerPeer) {
    node.voteForPeer = function (peerId, roundId = 1) {
        return Node.prototype.vote.call(this, valuesPerPeer[peerId], roundId);
    };
}

function stealKey(node) {
    return node.secret;
}

function forgeVote(victimNodeId, stolenSecret, value, roundId = 1, keyVersion = 1) {
    return {
        nodeId: victimNodeId, value, roundId, keyVersion,
        signature: sign(victimNodeId, value, stolenSecret, roundId, keyVersion)
    };
}

module.exports = { resetNode, makeByzantine, makeEquivocator, stealKey, forgeVote };
