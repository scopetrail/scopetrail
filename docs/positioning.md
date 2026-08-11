# ScopeTrail vs. Authproof vs. PipeLab

Three projects are building signed receipts for agent actions, from three different points in the chain. None of them compete — each is honest evidence about a different moment, and together they cover before, during, and after.

| | Moment | What it proves | Who signs |
|---|---|---|---|
| **Authproof — Delegation Receipt Protocol** | Before the action | What the human consented to | The user |
| **PipeLab — Agent Action Receipts** | During the action | What actually crossed the wire at one boundary | A mediator proxy |
| **ScopeTrail — OBO Audit Receipt** | After the action, across the whole chain | Whether the final action stayed inside the root human consent, N hops later | The issuer, over the full delegation chain |

## Authproof: pre-execution consent

Authproof's Delegation Receipt Protocol is an individual IETF draft (`draft-nelson-agent-delegation-receipts`, v05, May 2026, informational — not IETF-endorsed) with an MIT-licensed SDK and a hosted service. The *user* signs an Authorization Object — scope, boundaries, an operator-instruction hash, a model-state commitment — anchored to an append-only transparency log **before the agent runs**. It secures the user↔operator relationship: proof of what you agreed to, at the moment you agreed to it.

What it doesn't cover: whether an action three hops downstream, taken by an agent holding a token exchanged from that original grant, actually stayed inside what was authorized. That's a different question, asked at a different time, and Authproof's artifact isn't built to answer it.

## PipeLab: runtime mediator evidence

PipeLab (Pipelock) ships "Agent Action Receipts": Ed25519-signed, hash-chained records emitted by a mediator proxy on every HTTP/MCP/WebSocket action it adjudicates, offline-verifiable, packaged as "Audit Packets" aimed at SOC 2/HIPAA/PCI audiences. It's commercial, CNCF-landscape-listed, ships four open verifiers, and has stated plans to push the format into CoSAI/IETF/OASIS.

Its receipt is strong, independent evidence of what the mediator saw and allowed — produced outside the agent's own trust boundary, which matters. What it doesn't do: verify that the mediated action traces back to a specific human's original consent through every hop of a multi-agent chain. It's evidence at one boundary, not a verdict over the whole path.

## ScopeTrail: post-hoc chain-of-consent verification

ScopeTrail's OBO Audit Receipt answers the question neither of the above is built to answer: **did this specific action, taken by this specific agent, N hops from the human, stay inside the human's original authorization — and if not, where did it break?**

It does this by verifying the full delegation chain — root consent, every intermediate hop's scope, the final action — against a canonical, Ed25519-signed record shaped as a W3C Verifiable Credential. Verification is stateless: any third party checks a receipt with nothing but the issuer's public key, no callback, no vendor dashboard. This is live today, not a claim on paper — the issuer's JWKS is hosted at `https://scopetrail.github.io/.well-known/jwks.json`, and a real multi-hop receipt is published and independently verifiable at `at://did:plc:bty3gmskhla7rwblq5zl5jm5/dev.scopetrail.auditReceipt/00MSNYOYEE8DED5E8457E895C30683` — `valid: true`, no keys shipped with the verifier.

What ScopeTrail doesn't do: it isn't a token issuer, a policy engine, or a runtime gateway. It doesn't decide what a human should be allowed to authorize (Authproof's ground), and it doesn't sit in the request path adjudicating traffic (PipeLab's ground). It reads the tokens those systems already produce and turns them into a portable verdict.

## Why the triangle, not a fight

A complete agentic trust stack plausibly wants all three: proof of consent before the agent runs, proof of what happened at the enforcement boundary, and proof that the two stayed connected through every hop in between. Authproof and PipeLab are both credible, both shipping, both converging on "signed receipts" from their own side of the problem. ScopeTrail is the corner of that triangle that was empty — the multi-hop, human-readable, statelessly-verifiable link back to root consent.

Apache-2.0, zero runtime dependencies, interoperable with RFC 8693 `act` chains and Auth0's AAP claims on the way in.

## Sources

- [draft-nelson-agent-delegation-receipts (IETF datatracker)](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/)
- [PipeLab — Agent Action Receipts](https://pipelab.org/learn/agent-action-receipts/)

Authproof draft version/status and PipeLab's live pricing/feature set are current as of a July 2026 landscape review; both drafts and product pages change on their own cycles and are worth a fresh check before relying on the specifics here.
