
# TLS 1.3 + Remote Attestation: <br>Compound-Authenticated Conveyance Models

ProVerif models for TLS 1.3 composed with RFC9334 remote attestation (background-check and passport conveyance), evaluating compound authentication via an ephemeral KEM key (EKK) in addition to the standard TLS signing key across 3 timing windows: intra-, post-, and hybrid composition.

## Problem statement

The **[SEAT WG Charter](https://datatracker.ietf.org/doc/charter-ietf-seat/)** explicitly requires that the solution "will allow per-connection freshness of Evidence and **Attestation Results**."

## Approach

Previous approaches hashed the connection key directly into the hardware quote, creating a static binding without integration of live session material. If the connection key leaked, an attacker could spoof the session entirely, regardless of the attestation key's integrity. To resolve this vulnerability, these models introduce an Ephemeral KEM Key (EKK) challenge-response that dynamically binds the attestation to the live handshake transcript. This approach demonstrates compound and injective agreement (`ClientReceivesAppData` / `ServerSendsAppData`, `inj-event`) all the way to the application-data transport stage, providing insight beyond the end of the initial TLS handshake.

> **This is a work in progress,** [released under the Apache 2.0 license](https://github.com/nathanaelritz/dual-pop-atls-conveyance-models/tree/main#copyright-and-license).
> 
> *Real-world implementation and ongoing refinements to these approaches are expected to change over time.*

### HPKE object security and Evidence privacy

In `intra-background`, the HPKE Object Security Key (`privOSK`) is minted and immediately leaked onto the network alongside `pubOSK` (`out(io, privOSK)`), by construction. This deliberately hands the attacker full read access to the Evidence relayed to the Verifier — Evidence confidentiality-in-transit is explicitly *not* part of the security claim for this model; however, it does demonstrate that Evidence can be made opaque to an RP for privacy. Furthermore, the models demonstrate that even with full read access, the attacker still can't forge, replay, or splice Evidence to affect the outcome.

## Results

An ephemeral KEM Key (`EKK`) Proof-of-Possession mechanism provides compound-authentication when reliance on AEK is not available (such as when working with the Passport conveyance model). This provides a second, structurally independent proof from the `privCSK` signature on `CertificateVerify`.

🟢 = Single key is sufficient to protect app-data-level injective agreement

⚪ = Gap - key not effective in protecting injective agreement alone

| Verification Lifecycle & Attestation Typology | Connection Signing Key (`CSK`/`LTK`) | Ephemeral KEM Key (`EKK`) | Attestation Environment Key (`AEK`/`AK`) |
| --- | --- | --- | --- |
| **Background-Check** |  |  |  |
| ↳ [Intra-handshake](https://github.com/nathanaelritz/dual-pop-atls-conveyance-models/tree/main/models/intra/intra-background-check) | 🟢 | 🟢 | 🟢 |
| ↳ [Hybrid Post-handshake](https://github.com/nathanaelritz/dual-pop-atls-conveyance-models/tree/main/models/post/hybrid-passport-cache-background-check) | 🟢 | 🟢 | 🟢 |
| ↳ *(Prior Art)* | 🟢 | ⚪ | ⚪ |
| **Passport** |  |  |  |
| ↳ [Intra-Handshake](https://github.com/nathanaelritz/dual-pop-atls-conveyance-models/tree/main/models/intra/intra-passport) | 🟢 | 🟢 | ⚪ |
| ↳ [Post-Handshake only](https://github.com/nathanaelritz/dual-pop-atls-conveyance-models/tree/main/models/post/post-passport-no-cache) | 🟢 | 🟢 | ⚪ |
| ↳ *(Prior Art)* | 🟢 | ⚪ | ⚪ |

### EKK compound authentication mechanism

1. Verifier's AR asserts `(VM_S, pubCSK, pubAEK, pubEKK)` — `pubEKK` bound into the AR, independent of `pubCSK`.


2. Client encapsulates a fresh secret to `pubEKK` (`EKKEncaps`).


3. Server proves live possession of `privEKK` bound to the session-binding-value (`sbv`), such as the running hash transcript, by decapsulating (`EKKDecaps`) and returning `ekk_pop = hmac(StrongHash, b2mk(ekk_secret), sbv)`.



## Identity modeling

```
VM_S / privCSK   — per-tenant workload identity, signs CV. 
                   (may leak — LCSK/LeakedCSK)

ID_S / privLTK   — physical machine, signing key assumed secure
   └─ delegates signing authority: `sign(privLTK, (VM_S, pubCSK))`
   
privEKK          — per-workload ephemeral KEM key (may leak — LEKK/LeakedEKK)
privAEK          — per-machine attestation key (may leak — LAK/LeakedAEK)
privARK          - Verifier's Attestation Result Key, assumed secure

```

`VM_S` gets its own SNI, distinct from `ID_S`.

## Acknowledgements

This work is a unique adaptation and extension incorporating input from the following prior art:

* [Identity Crisis in Confidential Computing: Formal analysis of attested TLS protocols](https://github.com/CCC-Attestation/formal-spec-id-crisis/tree/main)
* [Intra-handshake.fail (CVE-2026-33697): High-severity CVE in Attested TLS](https://www.researchgate.net/publication/408219182_Intra-handshakefail_CVE-2026-33697_High-severity_CVE_in_Attested_TLS)
* [FATT Chance: On the Robustness of Standalone and Hybrid ML-KEM Key Exchange in TLS 1.3](https://eprint.iacr.org/2026/1147.pdf)
* [Verified Models and Reference Implementations for the TLS 1.3 Standard Candidate](https://ieeexplore.ieee.org/document/7958594)

Thank you to all involved authors and researchers!

## Copyright and License

Copyright 2017 Bhargavan et al.<br>
Copyright 2026 Sardar et al.<br>
Copyright 2026 Nathanael Ritz.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
