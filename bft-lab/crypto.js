const crypto = require("node:crypto");

function generateKeys() {
    return crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" }
    });
}

function validVoteShape(vote) {
    return vote !== null && typeof vote === "object" &&
        typeof vote.nodeId === "string" && vote.nodeId.length > 0 &&
        Number.isSafeInteger(vote.roundId) && vote.roundId > 0 &&
        Number.isSafeInteger(vote.keyVersion) && vote.keyVersion > 0 &&
        ((typeof vote.value === "number" && Number.isFinite(vote.value)) ||
            typeof vote.value === "string");
}

function payload(vote) {
    if (!validVoteShape(vote)) throw new Error("Malformed vote");
    // Sign the domain, identity, round, key version and typed value.
    return Buffer.from(JSON.stringify([
        "bft-lab-v1", vote.nodeId, vote.roundId, vote.keyVersion, vote.value
    ]));
}

function signVote(vote, privateKey) {
    return crypto.sign(null, payload(vote), privateKey).toString("base64");
}

function verifyVote(vote, publicKey) {
    if (!validVoteShape(vote) || typeof vote.signature !== "string" ||
        !/^[A-Za-z0-9+/]{86}==$/.test(vote.signature)) return false;
    try {
        return crypto.verify(
            null, payload(vote), publicKey, Buffer.from(vote.signature, "base64")
        );
    } catch {
        return false;
    }
}

// Positional helpers retained for the workshop's attack examples.
function sign(nodeId, value, secret, roundId = 1, keyVersion = 1) {
    return signVote({ nodeId, value, roundId, keyVersion }, secret);
}

function verify(nodeId, value, publicKey, signature, roundId = 1, keyVersion = 1) {
    return verifyVote({ nodeId, value, roundId, keyVersion, signature }, publicKey);
}

module.exports = { generateKeys, validVoteShape, signVote, verifyVote, sign, verify };
