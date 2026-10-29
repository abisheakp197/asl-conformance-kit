# Architectural & Integration Review: ASL Conformance Kit & NTI Runtime Sidecar

**Author:** Principal Systems Architect & Lead Integration Engineer
**Target Architecture:** NTI (Non-Trivial Isolation / Next-Gen Agent Architecture)
**Evaluated Repository:** `asl-conformance-kit` (Abisheak P. / ASL Conformance Lab)
**Status:** Architectural Integration & Conceptual Fusion Report

---

## Executive Summary

The ASL Conformance Kit developed by Abisheak P. represents an exemplary, source-free verification harness for AI agent containment, boundary enforcement, and cryptographic attestation. Operating under a strict 3,000-line stdlib-only Trusted Compute Base (TCB) budget, ASL achieves an outstanding L4.5 containment level (`Full Kernel + Mediated` under Linux/WSL2 and `Architecture Verified` under Windows).

This report provides a deep architectural breakdown of ASL’s internal mechanics, execution pathways, kernel containment strategies, and multi-agent swarm controls. Furthermore, it details how the **NTI Runtime Sidecar**—handling Principal-Bound Identity and post-quantum Dilithium5 / ML-DSA-87 execution proofs—will integrate into ASL’s verification harness to form a unified, enterprise-grade agent safety standard.

---

## 1. End-to-End Workflow Map

### 1.1 Ingestion & Execution Path (`conformance/verify_vectors.py`)

The entry point for independent vector verification is `conformance/verify_vectors.py`. It operates without third-party dependencies or imports from `asl`, ensuring clean-room third-party auditability.

```
+--------------------------+     +----------------------------------+
| conformance/vectors/*.json | --> | conformance/verify_vectors.py     |
+--------------------------+     +----------------------------------+
                                                 |
                                     1. Strict JSON Parsing
                                     2. Canonicalization
                                     3. Field & Schema Validation
                                     4. HMAC-SHA256 / Hash Verification
                                                 v
                                 +----------------------------------+
                                 | Console Output / Verification    |
                                 | "checked N vector cases, 0 fail" |
                                 +----------------------------------+
```

1. **Discovery & Globbing:** `verify_vectors.py` locates `conformance/vectors/*.json` using Python's stdlib `Path.glob()`.
2. **Family Dispatch:** Each JSON file specifies a `family` field (`canonical-json`, `argument-hashing`, `token-mint-verify`, `attestation-v1`, `boundary-wire-v1`, `audit-chain`), which maps directly to dedicated verifier functions in the `FAMILIES` dictionary.
3. **Strict JSON Ingestion (`parse_strict_or_error`):**
   - Disallows duplicate keys using a custom `object_pairs_hook`.
   - Rejects non-finite floating-point values (`NaN`, `Infinity`, `-Infinity`) via `parse_constant`.
   - Enforces recursion depth limits ($\le 64$) and validates UTF-8 string encoding.
4. **Canonicalization Engine (`canonical_json` / `canonical_bytes`):**
   - Re-implements RFC 8785 JSON Canonicalization Scheme (JCS).
   - Keys are sorted lexicographically (`sort_keys=True`).
   - Standard separators without whitespace (`separators=(",", ":")`).
   - Encoded cleanly to raw UTF-8 bytes.

### 1.2 Input / Output Data Structures & Receipts

- **Inputs:** JSON vector definitions carrying input payloads, operation types (`op`), wire format tokens, expected hashes/signatures, or explicit negative error cases (`expect: "deny"` or `"error"`).
- **Processing:** Re-computes cryptographic digests (SHA-256) or HMAC-SHA256 signatures over `canonical_bytes(payload)` using `FAKE_KEY` (`00112233...`).
- **Output / Terminal Evidence:**
  - `verify_vectors.py` prints test counts and exits with status code `0` on 0 failures, or `1` on failure.
  - In full-stack operations, evidence is collated into signed JSON/Markdown evidence reports (`docs/signed-evidence-report.json`) and path-free benchmark receipts (`conformance/benchmarks/receipts/*.json`).

### 1.3 Lifecycle of a Single Test Case

To illustrate the exact lifecycle from ingestion to signed receipt verification, consider a boundary wire case (`valid witness checkpoint`):

```
[ Vector File ] -> JSON string ingested from boundary_v1.json
         |
[ Strict Parser ] -> Validates schema ("asl.witness.v1"), version (1), algorithm ("HS256")
         |
[ Canonicalizer ] -> Drops signature field ("host_hmac"), sorts remaining keys into canonical bytes
         |
[ Crypto Engine ] -> HMAC-SHA256(FAKE_KEY, canonical_bytes) -> Computed Hex Signature
         |
[ Constant-Time ] -> hmac.compare_digest(computed_hex, wire_hex)
         |
[ Verdict / Receipt] -> Recorded as OK in benchmark receipt / evidence summary
```

---

## 2. Conceptual Architecture Review

### 2.1 P9 External Boundary: Witness Checkpoint & Hardware Kill-Switch

ASL models physical off-box isolation (L5 dependencies) through strict software wire contracts declared in `conformance/vectors/boundary_v1.json`:

```
                    +-----------------------------+
                    |  Host (Safety Gateway)      |
                    +-----------------------------+
                               |     ^
           asl.witness.v1      |     |  Witness Ack
          (Signed Host HMAC)   v     | (Different Witness Key)
                    +-----------------------------+
                    |  External Witness Node      |
                    +-----------------------------+

                    +-----------------------------+
                    | Hardware Kill Actuator (ATX)|
                    +-----------------------------+
                               ^
         asl.hw_kill.v1        |
     (Monotonic Nonce Ledger)  |
                    +-----------------------------+
                    | Triggering Authority        |
                    +-----------------------------+
```

1. **Witness Checkpoint (`asl.witness.v1`):**
   - Structures state using `run_id`, `seq_no`, `audit_head_hash`, `policy_hash`, `timestamp_ns`, and `host_hmac`.
   - Requires an off-box witness to verify `host_hmac` and respond with an acknowledgment signed by a **different witness key**. If the host key could generate the acknowledgment, the witness would not be independent.
2. **Hardware Kill Switch (`asl.hw_kill.v1`):**
   - Transmits a signed termination payload containing `target_node_id`, `reason_code` (e.g., `policy_violation`, `witness_disagreement`), `monotonic_nonce`, and `hmac_sig`.
   - **Replay Protection:** Recipient nodes maintain a monotonic nonce ledger high-water mark. Any command with `nonce <= ledger[target_node_id]` is immediately rejected as a replay attack. Crucially, signature verification occurs *before* nonce ledger evaluation to prevent unauthenticated nonce-exhaustion denial of service.

### 2.2 L4.5 Kernel Confinement & Socket-Level Egress Control

ASL achieves full kernel-level egress confinement (proven under Ubuntu / WSL2 in `docs/kernel-confinement.md`) through dual-layer network namespace isolation (`unshare --net` and `bubblewrap --unshare-all`).

```
+-------------------------------------------------------------------+
| Host Environment / Gateway                                        |
|                                                                   |
|   +-----------------------------------------------------------+   |
|   | Sandboxed Agent Child Process                             |   |
|   | (unshare --net / bwrap --unshare-all)                     |   |
|   |                                                           |   |
|   | Direct IP Route: NONE (0.0.0.0 / Loopback BLOCKED)        |   |
|   +-----------------------------------------------------------+   |
|                                 |                                 |
|                         AF_UNIX Socket                            |
|                        (Mediated Channel)                         |
|                                 v                                 |
|   +-----------------------------------------------------------+   |
|   | Mediated Egress Gateway (asl.egress)                       |   |
|   | 1. Per-hop DNS resolution & IP-pinning                    |   |
|   | 2. Capability Token Validation                            |   |
|   | 3. CIDR / Loopback / Metadata / Rebinding Guard           |   |
|   +-----------------------------------------------------------+   |
|                                 |                                 |
|                          Outbound HTTPS                           |
|                                 v                                 |
|                       External Destination                        |
+-------------------------------------------------------------------+
```

- **No Direct IP Route:** Inside the network namespace, direct socket connections to loopback (`127.0.0.1`), LAN, or public internet return `NO_ROUTE`.
- **AF_UNIX Mediated Channel:** Linux network namespaces do not partition local IPC domain sockets (`AF_UNIX`). The sandbox communicates exclusively over a Unix domain socket to the ASL gateway.
- **IP-Pinning & Redirect Control (`asl.egress.ipguard` / `urlguard`):**
  - Resolves DNS once per HTTP hop.
  - Validates destination IP addresses against disallowed lists (private RFC 1918 ranges, 127.0.0.0/8, 169.254.169.254 cloud metadata, IPv6-mapped IPv4, octal/hex/decimal numeric IP tricks).
  - Pins TCP socket connections directly to the validated IP address, preventing DNS rebinding between validation and `connect()`.
  - Re-evaluates every redirect URL hop independently; any redirect attempting to hop to a private or off-allowlist address triggers immediate channel denial.

### 2.3 700-Agent Swarm Simulation & Anti-Collusion Framework

ASL manages high-density multi-agent deployments through its P4 Swarm Governor (`src/asl/swarm/`):

1. **Identity & Isolation:** Every agent receives a non-transferable, gateway-minted identity token (`agent_id` + `run_id`). Workspace directories are strictly compartmentalized per agent (`<workspace>/agents/<agent_id>/`).
2. **Mediated Inter-Agent Bus (`SwarmBus`):**
   - Inter-agent communication is schema-validated and canonicalized.
   - **Data vs. Authority:** Peer text is treated exclusively as data. Instructions containing control tokens, `GO` commands, or privilege widenings are stripped of authority; an agent cannot mint or widen capabilities on behalf of another.
3. **Collusion Containment & Anti-False-Alarm Tripwires:**
   - Tracks global and per-agent metrics: step counts, messages/sec, monetary spend, and covert channel bit budgets.
   - **Tighten-Only Tripwire:** Distributed network sweeps, concurrent queue flooding, or instruction laundering elevate the containment state monadically: `THROTTLE -> FREEZE -> KILL`.
   - Deterministic 700-agent simulations (`S01` to `S06`) demonstrate **0 false alarms** on legitimate workloads while containing 100% of collusive attack scenarios.

---

## 3. Integration Points (NTI + ASL)

Our NTI (Non-Trivial Isolation) architecture expands ASL’s single-host containment into an enterprise-wide standard using **Principal-Bound Identity** and **Dilithium5 (ML-DSA-87) Post-Quantum Signatures**.

```
+-------------------------------------------------------------------+
| NTI Runtime Sidecar                                               |
|  - Principal-Bound Identity (PBI)                                 |
|  - Dilithium5 / ML-DSA-87 Quantum Proof Engine                    |
+-------------------------------------------------------------------+
                                 |
                      Attestation & Token Seam
                                 v
+-------------------------------------------------------------------+
| ASL Conformance Harness                                           |
|  - Capability Token Verification (tokens.py / verify_vectors.py)  |
|  - Algorithm Agility Registry (algorithm.py)                      |
|  - Attestation Format (attestation_v1.json)                        |
|  - Risk Signal & Witness Pipeline (signals.py / boundary_v1.json) |
+-------------------------------------------------------------------+
```

### 3.1 NTI Runtime Sidecar Plug Points

| ASL Component | File / Path | Integration Mechanism |
|---|---|---|
| **Crypto Agility Registry** | `conformance/verify_vectors.py` & `src/asl/core/algorithm.py` | Register `ML-DSA-87` / `Dilithium5` alongside `HS256` in `ALGORITHM_ID` dispatcher. |
| **Token Format Engine** | `conformance/vectors/tokens.json` & `verify_token()` | Extend token wire format (`.body.sig`) to accept variable-length post-quantum signatures alongside HMAC hex signatures. |
| **Attestation Wire Header** | `conformance/vectors/attestation_v1.json` & `verify_attestation()` | Ingest NTI execution proofs in `X-ASL-Attestation` headers, mapping NTI Principal Identity hashes to `policy_hash` and `audit_head_hash`. |
| **Risk Signal Provider** | `src/asl/risk/providers.py` & `conformance/vectors/boundary_v1.json` | Plug NTI runtime sidecar telemetry as an external `RiskSignal` adapter over Unix sockets (`AF_UNIX`). |

### 3.2 Post-Quantum Handshake (ML-DSA-87 / Dilithium5)

To execute NTI Dilithium5 signature verification within ASL vector harnesses:

1. **Algorithm Identifier Registration:**
   In `verify_vectors.py`:
   ```python
   SUPPORTED_ALGORITHMS = {"HS256", "ML-DSA-87", "DILITHIUM5"}
   ```
2. **Handshake Verification Point:**
   Inside `verify_token()` and `verify_attestation()`, replace/augment the HMAC check:
   ```python
   if payload["algorithm_id"] in ("ML-DSA-87", "DILITHIUM5"):
       # Handshake point for NTI Post-Quantum verification engine
       ok = nti_pq_verify(
           public_key=payload["key_id"],
           message=canonical_bytes(payload),
           signature=signature_bytes
       )
   ```
3. **Canonical Byte Consistency:**
   NTI sidecars will consume ASL's JCS implementation (`canonical_bytes()`), ensuring identical byte serialization prior to post-quantum signature verification.

---

## 4. Gap Analysis

Abisheak P.’s ASL Conformance Kit is a masterpiece of minimalist trusted-core engineering. Below is the comparative analysis highlighting what ASL solved brilliantly versus what NTI adds to build the unified standard.

```
+------------------------------------------------------------------+
| ASL Conformance Kit (Single-Host Containment Foundation)          |
|  - 3k Line TCB Budget, Zero Third-Party Dependencies             |
|  - L4.5 Full Kernel Egress Confinement & AF_UNIX Mediation        |
|  - 250/250 Public Exploit Containment & 700-Agent Swarm Sim       |
|  - Monotonic Nonce Hardware Kill & Witness Wire Contracts        |
+------------------------------------------------------------------+
                                 +
                                 | Expanded Scope
                                 v
+------------------------------------------------------------------+
| NTI Standard Extension (Cross-Enterprise Trust Layer)             |
|  - Post-Quantum Cryptography (ML-DSA-87 / Dilithium5 Signatures)   |
|  - Cross-Enterprise PKI Federation & Key Revocation Networks     |
|  - Physical BMC/IPMI & Hardware GPIO Relay Actuation              |
|  - Live Frontier Model Swarm Weights & Multi-Tenant Identity      |
+------------------------------------------------------------------+
```

### 4.1 Comparative Matrix

| Domain | ASL Conformance Kit Achievement | NTI Standard Extension |
|---|---|---|
| **Scope of Trust** | Single-host local containment & audit logging. | Cross-enterprise federated identity & global trust domain. |
| **Cryptography** | HMAC-SHA256 (HS256) with algorithm agility hooks. | Post-Quantum Cryptography (ML-DSA-87 / Dilithium5). |
| **Kernel Confinement** | Proven Linux network namespaces (`unshare`/`bwrap`). | Cross-platform (Linux eBPF + Windows HV isolation). |
| **Off-Box Witness** | Signed wire contracts (`asl.witness.v1`). | Multi-party threshold signature witness network. |
| **Hardware Actuation** | Wire contracts (`asl.hw_kill.v1`) + software simulators. | Production BMC/IPMI & physical PDU relay adapters. |
| **Agent Swarm** | Deterministic scripted 700-agent collusion harness. | Live frontier model swarm execution & weight monitoring. |

### 4.2 Summary of Absorption & Next Steps

1. **Absorb Trusted Core Architecture:** Retain ASL’s 3,000-line TCB budget constraint, canonical JSON parser, and fail-closed design philosophy.
2. **Incorporate Conformance Vectors:** Standardize `conformance/vectors/*.json` across all NTI runtime sidecar builds to ensure continuous compatibility.
3. **Upgrade Cryptographic Primitives:** Extend `boundary_v1.json` and `tokens.json` to feature ML-DSA-87 vector suites.
4. **Deploy Joint Harness:** Execute NTI Runtime Sidecars within ASL’s L4.5 kernel confinement harness for comprehensive end-to-end evaluation.

---
*Report compiled successfully for NTI Architecture & Integration Roadmap.*
