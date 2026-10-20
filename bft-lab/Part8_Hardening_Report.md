# Part 8: Hardening a BFT System

COMSM0122: Fundamentals of System Security

Workshop 2 implementation and evaluation report

20 October 2026

## Implementation outcome

All five Part 8 tasks have been implemented in the local JavaScript simulator: equivocation detection, key rotation and revocation, validator admission control, quorum validation and verifiable commit certificates. Normal operation still commits 100, while the selected attacks are detected or rejected at the relevant checks.

The recorded validation run passed 42 automated tests with 0 failures. All 10 additional command checks completed with exit code 0, including the combined demonstration, certificate verification and individual scenarios. The execution runtime was Node.js v26.12.0.

- 8.1 Equivocation: D's conflicting signed votes were recorded; only A, B and C supported the commit.
- 8.2 Key protection: The stolen current key initially verified. Old-key votes failed after rotation; revoked A could no longer vote.
- 8.3 Membership: X1-X4 were rejected. An impostor claiming A's name also failed signature verification.
- 8.4 Quorum: Quorum 2 was blocked. A 2-2 split with quorum 3 produced NO CONSENSUS.
- 8.5 Certificates: The certificate for 100 verified with A, B and C. Changing its value to 999 invalidated it.

## Common validation path

The starter simulator counted every supplied vote. The updated path first checks the configured quorum, then validates membership, revocation status, round, key version and signature. It counts each approved identity once, excludes authenticated equivocators from the batch, and commits only after enough eligible votes agree.

The original predictable-secret hash has been replaced with Ed25519 signatures using Node.js built-in cryptography. Each signature covers a protocol identifier, sender, round, key version and typed value. Public keys are sufficient for verification. Fresh keys are generated on each run; exported evidence contains no private keys.

Requirement source: workshop manual, Part 8, pages 9-12 . Execution evidence: evidence/part8-results.json and evidence/validation-summary.json .

## 8.1 Detect equivocation

The attack uses validator D's legitimate key to sign 100 for A, 50 for B and 75 for C in the same round. Each vote is authentic. The violated assumption is that an approved validator gives a consistent vote for a particular round.

Implementation. evidence.js indexes authenticated messages by round and sender. It retains the first message and a conflicting signed message, including recipient metadata. simulator.js removes the sender's earlier eligible vote when a conflict appears and excludes further votes from that sender in the batch. Signature verification happens before logging evidence, preventing forged conflicts from being used to frame a validator.

Experiment. The demonstration supplies A, B and C's votes for 100, followed by D's three conflicting messages. It produces one conflict evidence record for D and a certificate signed only by A, B and C. The commit value is 100. Repeated identical votes count once; a different value in a later round is allowed.

```text
npm run equivocation
EQUIVOCATION DETECTED: D in round 1
COMMITTED: 100
COMMIT CERTIFICATE: signed by A, B, C
```

Effect and assumption. Detection requires the collector to receive both signed values. The complete batch models recipients sharing evidence before a decision. Recipient labels are local audit metadata; the conflicting values and round are signed. Evidence remains in memory during execution and is exported by the demonstration.

## 8.2 Strengthen key protection

A stolen current private key enables an attacker to sign a valid vote for 999 as A. The demonstration checks this explicitly before applying a defence. Authenticity alone cannot distinguish the attacker from the key's legitimate holder.

Implementation. Node.rotateKey() creates a fresh Ed25519 pair and increments the key version. ValidatorRegistry.updateKey() applies the new public key through an explicit administrative operation; it rejects rollback, reuse of the same key and updates to revoked identities. ValidatorRegistry.revoke() blocks all future votes from that identity under the current policy.

Experiment. After A rotates from version 1 to version 2, a vote carrying the old version is rejected as obsolete. A second forged vote that claims version 2 but uses the stolen old key fails its signature check. A's new key succeeds. After revocation, A is rejected and B, C and D still commit 100 with quorum 3.

Effect and assumption. Rotation limits future use of a compromised key once the trusted update is applied. The demonstration uses an explicit rotation; automatic scheduling and compromise detection are outside this implementation. Revocation keeps the original four-member electorate, so it cannot silently weaken quorum.

## 8.3 Prevent Sybil attacks

The attack introduces X1, X2, X3 and X4 as extra participants, each voting for 999. It also introduces a separate node named A with an unrelated key. The trust assumption being protected is that voting rights belong only to approved identities authenticated with their registered keys.

Implementation. registry.js takes a snapshot of the approved A-D public configuration before attacker identities are added. simulator.js uses this independent registry for membership checks and quorum calculation. Unknown identities are rejected, approved names must authenticate with their registered key, and duplicate votes from one identity cannot increase its voting power.

Experiment. All four X identities are rejected as unapproved. The impostor named A fails signature verification. The electorate remains four, the quorum remains three, and the genuine A-D votes commit 100. An additional automated test repeats a single authenticated vote twenty times; it still counts once and cannot produce a commit.

Effect and assumption. The administrator must control the approved roster. The default simulator constructor treats its initial nodes as trusted membership; the Sybil scenario therefore supplies an independent registry captured before the attack. The policy cannot protect against an administrator deliberately approving attacker-controlled identities.

## 8.4 Protect quorum rules

The preserved starter attack splits four votes between 100 and 50, with two votes for each value. At quorum 2 it reports SAFETY VIOLATION because both values qualify. This original result was reproduced from the project backup and saved as evidence/original-quorum-baseline.txt.

Implementation. quorum.js requires an integer quorum between floor(2n/3) + 1 and n, where n is the approved membership count. The simulator checks this before each round and compares vote counts directly with the validated threshold. A custom reached() method cannot bypass the check.

```text
n = 4
minimum = floor(2 * 4 / 3) + 1 = 3
allowed quorum values: 3 or 4
```

- 2-2 split; requested quorum 2: Blocked: Unsafe quorum size: 2; expected 3 to 4
- 2-2 split; quorum 3: NO CONSENSUS
- Four votes for 100; quorum 3: COMMITTED: 100

Effect and assumption. For four validators with at most one Byzantine participant, two sets of three overlap in at least two identities, including an honest identity. This supports quorum reasoning under the stated fault bound. The check protects the configuration path; a developer able to replace the validation code itself remains inside the trusted code boundary.

## 8.5 Build a commit certificate

A plain COMMITTED message records the decision without its supporting evidence. The new certificate records which distinct approved identities signed the same value in the same round, allowing a separate verifier to check the decision.

Implementation. certificate.js builds a certificate containing the protocol identifier, round, committed value, quorum and complete supporting signed votes. The simulator verifies it before reporting a commit. The verifier checks membership, revocation, key version, signature, round and value, rejects duplicate signers, and requires the independently configured quorum.

The demonstration exports evidence/commit-certificate.json and a separate public configuration snapshot, evidence/trusted-config.json. verify-certificate.js reads both without needing any validator's private key. The configuration is a trust input: an actual verifier must obtain it through a trusted channel rather than accepting keys asserted by the certificate.

Experiment. A, B and C vote for 100 while D votes for 50. The simulator commits 100 and stores only the three supporting signatures in its certificate. Independent verification succeeds. Changing the certificate value to 999 fails with Value mismatch. Automated tests also reject changed rounds, invalid signatures, duplicate signers, insufficient signatures, unapproved signers and weakened quorum metadata.

```text
npm run part8
npm run verify-certificate

{
  "valid": true,
  "signers": ["A", "B", "C"]
}
```

Audit behaviour. The simulator stores independent copies of its audit results and certificates. Editing the returned result does not rewrite the stored record. These are in-memory records; the demonstration exports them to ordinary JSON files for inspection.

Effect and assumption. Verification proves that sufficient registered keys signed the stated value and round under the supplied policy. It depends on trusted membership and key information. The current registry applies current revocation and key state; historical verification needs an authenticated snapshot of the configuration that applied when the certificate was issued.

## Files to inspect

- certificate.js: Certificate construction and verification rules.
- verify-certificate.js: Independent command-line verification.
- evidence/commit-certificate.json: Saved certificate for 100, signed by A, B and C.
- evidence/trusted-config.json: Public keys and quorum for the saved certificate.
- evidence/part8-results.json: Full outcomes and signed equivocation evidence.

## Validation and reproduction

The delivered implementation passed 42 tests. The checks cover successful commits and failure paths: authenticated equivocation, forged accusations, key rotation, rollback, revocation, duplicate identities, repeated votes, invalid quorums, tampered certificates, replayed rounds, malformed votes and the distinction between numeric 100 and textual "100".

Validation timestamp (UTC): 2026-10-20T14:20:40.052Z. Detailed test output is in evidence/unit-tests.tap. Command exit codes and runtime details are in evidence/validation-summary.json.

```text
npm test
npm run part8
npm run verify-certificate

# Regenerate all logs and the validation summary
npm run validate
```

The project requires Node.js 18 or later and has no third-party package dependencies. Each run generates fresh keys, so signature bytes change while the checked outcomes remain reproducible. This report records the saved validation evidence.

## Safety, availability and scope

The hardening checks preserve the normal four-node commit and the three-honest, one-Byzantine example. Refusing a 2-2 split protects against a contradictory decision in that experiment, at the cost of making no progress in that batch. Likewise, revoking two of four validators leaves only two eligible votes and prevents a commit; the system keeps quorum three rather than lowering the threshold.

The simulator processes a complete batch in one process and compares evidence before deciding. Its local round counter prevents reusing a completed round within that instance. It does not implement network-wide evidence dissemination, view changes, cross-round locking, durable recovery or asynchronous liveness. These experiments establish the behaviour of the added checks; a complete distributed BFT protocol would require those further mechanisms.

Operational use would also require protected private-key storage, authenticated administration of rotation and revocation, agreed membership changes, persistent audit storage and a defined history of trusted configurations. An attacker who controls an approved current key can still sign a valid vote until that key is replaced or the identity is revoked.

