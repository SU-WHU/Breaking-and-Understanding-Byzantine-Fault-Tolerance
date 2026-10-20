# BFT Workshop Report (Parts 5–7)

## Part 5: Sybil Attacks and Membership Management

**Terminal Result:**

```
Original validator set
┌─────────┬────────┐
│ (index) │ Values │
├─────────┼────────┤
│ 0       │ 'A'    │
│ 1       │ 'B'    │
│ 2       │ 'C'    │
│ 3       │ 'D'    │
└─────────┴────────┘
After Sybil attack
┌─────────┬────────┐
│ (index) │ Values │
├─────────┼────────┤
│ 0       │ 'A'    │
│ 1       │ 'B'    │
│ 2       │ 'C'    │
│ 3       │ 'D'    │
│ 4       │ 'X1'   │
│ 5       │ 'X2'   │
│ 6       │ 'X3'   │
│ 7       │ 'X4'   │
└─────────┴────────┘
```

**Observation:**

In `sybil.js`, the validator set was expanded from originally 4 nodes (`A`-`D`) to 8 nodes (the attacker creates `X1`-`X4`). So this indicates that a weak identity admission mechanism allows an attacker to create fake identities in the system and eventually control over 50% of the network identities, thus diluting honest voting power and manipulating quorum thresholds.

**Answers of Reflective Questions:**

- In permissioned blockchains, the participance of nis determined by external governance or admission control mechanisms.
- Consensus protocols are only responsible for reaching agreement on a given set of messages, they cannot independently verify the mapping between physical entities and network identities.
- Blockchain systems prevent Sybil attacks by introducing economic cost mechanisms such as Proof of Work (consuming computational power) or Proof of Stake (staking assets), or, in the case of permissioned blockchains, by using a PKI-based whitelist.
- If an attacker controls the vast majority of identities, they would gain control over the quorum.

---

## Part 6: Quorum Reasoning and Safety

**Terminal Result:**

```
====================
Proposal: 100
====================
A voted 100
B voted 100
C voted 50
D voted 50

Vote Tally
┌─────────┬────────┐
│ (index) │ Values │
├─────────┼────────┤
│ 50      │ 2      │
│ 100     │ 2      │
└─────────┴────────┘
Required Quorum = 2

SAFETY VIOLATION!
Multiple values reached quorum:
┌─────────┬───────┬───────┐
│ (index) │ value │ votes │
├─────────┼───────┼───────┤
│ 0       │ '50'  │ 2     │
│ 1       │ '100' │ 2     │
└─────────┴───────┴───────┘
```

**Observation:**

In `quorum_tampering.js`, the required quorum threshold was artificially lowered to `2` in a 4-node network. When nodes `A` and `B` voted for `100`, and `C` and `D` voted for `50`, both values reached the modified quorum requirement simultaneously (2 votes each), thus triggering a `SAFETY VIOLATION`.
This proves that BFT safety depends strictly on $N \ge 3f + 1$ to prevent conflicting commits.

**Answers of Reflective Questions:**

- The modified quorum rule fail because it allows two disjoint subsets reach quorum requirements without any overlap.
- The lost property is quorum intersection (the guarantee that any two quorums share at least one honest node).
- Multiple values can reach quorum simultaneously as demonstrated when the threshold was lowered artificially, but not in correct BFT sennarios (where $N \ge 3f + 1$).
- To ensure that information/commit decisions from prior rounds are carried forward and conflicting decisions are mathematically impossible, future quorums must overlap with previous quorums.

---

## Part 7: Breaking BFT — Combined Sybil + Equivocation Attack

**Attack Strategy:**

In `bft_break_p7.js`, a combined Sybil + Equivocation (double-voting) attack fully breaks the system's availability and safety, without modifying the core consensus formula (the quorum rule $N \ge 3f + 1$). The attack is carried out in the following phases:

- **Phases 1 & 2 (baseline).** Verify that with $N=4$, a single equivocating node (D) cannot break consensus — the honest nodes A, B, C still meet the quorum (Quorum = 3), so the system remains safe.
- **Phase 3 (Sybil injection).** The attacker registers four fake identities (X1–X4). The total node count $N$ grows to 8 and the quorum threshold becomes 6, so the attacker now controls 50% of the identities, violating the $f < N/3$ assumption.
- **Phase 4 (break liveness/availability).** The attacker's four Sybil nodes all vote for a value conflicting with the honest proposal (50 vs 100), so the 4 honest votes can never reach the quorum of 6 → `NO CONSENSUS`.
- **Phase 5 (break safety).** The attacker makes X1–X4 send signed value `100` to honest nodes {A, B} and signed value `50` to honest nodes {C, D}, forming two conflicting 6-signature quorum certificates → `SAFETY VIOLATION`.

**Terminal Result:**

```
=== PHASE 1: Honest (N=4) ===

====================
Proposal: 100
====================
A voted 100
B voted 100
C voted 100
D voted 100

Vote Tally
┌─────────┬────────┐
│ (index) │ Values │
├─────────┼────────┤
│ 100     │ 4      │
└─────────┴────────┘
Required Quorum = 3

COMMITTED: 100

=== PHASE 2: Single equivocator (N=4) ===
D equivocates: A<-100 B<-100 C<-100 D<-50

====================
Proposal: 100
====================
A voted 100
B voted 100
C voted 100
D voted 50

Vote Tally
┌─────────┬────────┐
│ (index) │ Values │
├─────────┼────────┤
│ 50      │ 1      │
│ 100     │ 3      │
└─────────┴────────┘
Required Quorum = 3

COMMITTED: 100

=== PHASE 3: Sybil injection ===
Validators: A, B, C, D, X1, X2, X3, X4  (N=8, quorum=6, honest=4/8)

=== PHASE 4: Sybil + coordinated vote -> NO CONSENSUS ===

====================
Proposal: 100
====================
A voted 100
B voted 100
C voted 100
D voted 100
X1 voted 50
X2 voted 50
X3 voted 50
X4 voted 50

Vote Tally
┌─────────┬────────┐
│ (index) │ Values │
├─────────┼────────┤
│ 50      │ 4      │
│ 100     │ 4      │
└─────────┴────────┘
Required Quorum = 6

NO CONSENSUS

=== PHASE 5: Sybil + Equivocation -> SAFETY VIOLATION ===
Quorum = 6
Cert 1 (A,B see): A:100 B:100 X1:100 X2:100 X3:100 X4:100
Cert 2 (C,D see): C:50 D:50 X1:50 X2:50 X3:50 X4:50
Overlap = X1..X4 (attacker-only) -> no honest node links them

SAFETY VIOLATION! 100 and 50 are both committed.
```

**Observation:**

In `bft_break_p7.js`, the attacker first injects four fake validators (`X1`–`X4`), so it controls half the identities of an N=8 network (quorum rises to 6 while honest power stays 4/8). A single equivocator alone cannot break a correct quorum (Phase 2), but combined with Sybil the attack breaks consensus in two ways: (1) the 4 honest votes for `100` can never reach the quorum of 6, so the system deadlocks (`NO CONSENSUS`, liveness/DoS); (2) the fake identities equivocate — sign `100` to `{A,B}` and `50` to `{C,D}` — forming two valid 6-signature quorum certificates whose overlap is entirely attacker-controlled, so two conflicting values are both committed (`SAFETY VIOLATION`). This shows BFT safety depends not only on the `N ≥ 3f+1` quorum formula but also on a correct, non-inflatable membership set.

**Answers of Reflective Questions:**

- The violated trust assumption is identity/membership: that validator identities map one-to-one to independent honest participants, and at most `f` of them are faulty.
- It is a governance/admission-control issue, not protocol correctness — the quorum formula is still correct but was fed an untrustworthy validator set.
- Safety failed: two conflicting values (`100` and `50`) each reached quorum and were committed.
- Availability failed: in Phase 4 no value reached quorum, so the system stopped making progress (`NO CONSENSUS`).
- It could occur in a real deployment with weak admission control (e.g. permissionless PoS without anti-correlation, or a permissioned network lacking a validator whitelist); real systems resist it with governance, economic cost, and equivocation detection/slashing.
