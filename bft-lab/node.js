const { generateKeys, signVote, verifyVote } = require("./crypto");

class Node {
    constructor(id, honest = true) {
        this.id = id;
        this.honest = honest;
        this.keyVersion = 0;
        this.rotateKey();
    }

    rotateKey() {
        const { privateKey, publicKey } = generateKeys();
        this.secret = privateKey;
        this.publicKey = publicKey;
        this.keyVersion += 1;
        return this.publicInfo;
    }

    get publicInfo() {
        return {
            id: this.id, publicKey: this.publicKey, keyVersion: this.keyVersion
        };
    }

    vote(value, roundId = 1) {
        const vote = {
            nodeId: this.id, value, roundId, keyVersion: this.keyVersion
        };
        return { ...vote, signature: signVote(vote, this.secret) };
    }

    verifyVote(vote, publicKeyLookup) {
        return verifyVote(vote, publicKeyLookup(vote.nodeId));
    }
}

module.exports = Node;
