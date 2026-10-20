# Workshop 2: Breaking and Understanding Byzantine Fault Tolerance

Part 8 implements and demonstrates all five hardening tasks. The project uses
Node.js 18 or later and built-in modules only. No third-party packages are required.

## Run the work

Open a terminal in this directory, then run:

```powershell
npm test
npm run part8
npm run verify-certificate
```

`npm run part8` runs all five demonstrations and saves JSON evidence.
`npm run verify-certificate` independently checks the saved certificate against
the public keys and quorum in `evidence/trusted-config.json`.
The verifier must obtain that configuration from a trusted administrator.

To regenerate all execution logs and the validation summary:

```powershell
npm run validate
```

Individual scenarios:

| Command | Purpose |
| --- | --- |
| `npm run honest` | Four honest validators commit 100. |
| `npm run byzantine` | Three honest validators outvote one conflicting vote. |
| `npm run equivocation` | Detect and exclude a validator that signs conflicting values in one round. |
| `npm run key-theft` | Demonstrate compromise, key rotation and revocation. |
| `npm run sybil` | Reject unapproved identities and an impostor using an approved name. |
| `npm run quorum` | Reject quorum 2, demonstrate a safe split vote and normal agreement. |
| `npm run certificates` | Generate a certificate and detect a changed commit value. |

The original project was backed up outside this directory as
`Day2 Workshop/bft-lab-before-part8.zip`. The original workshop notes remain unchanged.
Attack commands now demonstrate the hardened behaviour.

## Part 8 implementation

| Task | Main files | Defence |
| --- | --- | --- |
| 8.1 | `evidence.js`, `simulator.js` | Compare authenticated messages by round and sender; retain conflicting signed evidence and exclude that sender's votes from the batch. |
| 8.2 | `node.js`, `registry.js`, `crypto.js` | Generate Ed25519 keys, rotate to a new version through a trusted registry update, and reject revoked identities. |
| 8.3 | `registry.js`, `simulator.js` | Keep an approved roster independent of incoming participants; check signatures and count each identity once per round. |
| 8.4 | `quorum.js`, `simulator.js` | Enforce `floor(2*n/3) + 1 <= quorum <= n`, with an integer quorum, and use the validated threshold directly. |
| 8.5 | `certificate.js`, `verify-certificate.js` | Store the round, committed value and distinct supporting signed votes; verify them against trusted configuration. |

Votes sign the protocol domain, validator identity, round, key version and typed
value. This replaces the starter code's hash of a predictable shared secret.
Verification uses public keys; evidence files contain no private keys.

The processing order is: validate quorum, validate each incoming vote, detect
duplicates and equivocation, tally eligible votes, then build and verify a
certificate. A sender's earlier vote is removed if a later authenticated message
reveals a conflict in the same batch. Different values in different rounds are
permitted. Old messages cannot be relabelled with a new round without invalidating
their signatures.

## Trust assumptions and limits

The administrator controls initial membership, public keys, rotation and
revocation. Incoming votes cannot authorise these changes. If an attacker is
approved as a validator, this admission policy cannot distinguish that attacker
from an approved participant.

Revocation does not reduce the configured membership or quorum. With four
approved validators, revoking one still permits three votes; revoking two stops
progress. Membership reconfiguration would need its own agreement procedure.

Key rotation stops future use of the old key once the trusted update is applied.
Before that update, a vote signed with a stolen current key remains authentic.
The demonstration performs an explicit rotation; it does not schedule rotations.
The current registry checks current credentials. Historical certificate
verification requires an authenticated snapshot of the public configuration that
applied to that round.

This is a synchronous, single-process vote simulator. Each round processes a
complete supplied batch; the evidence collector models recipients sharing their
messages. The `recipient` label is local audit metadata and is not signed.
Detection depends on both conflicting signed votes reaching the collector.
The simulator does not implement peer-to-peer evidence dissemination, durable
storage, view changes, cross-round locking, network partitions or asynchronous
liveness. Its local round counter prevents reusing a completed round within one
simulator instance. It is not a complete BFT protocol or a proof of distributed
consensus under arbitrary scheduling.

