# Standards summary: security baseline

Topic 21 of the standards reading list (new in spec run M2). Our summary,
at overview level, of FIPS 186-5 (digital signatures), RFC 5280 (X.509
certificate profile), NIST SP 800-57 Part 1 Rev. 5 (key management), and,
for operator authentication, FIPS 201-3 and NIST SP 800-73-5 (PIV) and
NIST SP 800-63B (authenticator assurance). For content integrity (IMG,
PE) and operator access (`specs/operator-access.md`).

This file makes no design choice. Which algorithms, certificates and
authenticators the product uses is a clean-side or project decision.

**[primary not read]**: NIST PDFs could not be read with the available
tools (the fetch tool cannot extract their text and no PDF renderer is
installed). For those, only NIST's publication or project pages were
used, and only what those pages say is given.

## 1. Digital signatures: FIPS 186-5 [primary not read]

From NIST's FIPS 186-5 publication page and NIST's Digital Signatures
project page:

- FIPS 186-5, Digital Signature Standard, published 2023-02-03,
  supersedes FIPS 186-4. NIST notes known issues to be fixed in a later
  update (errata list on the publication page).
- Purpose: signatures detect unauthorised changes to data, authenticate
  the signer, and support non-repudiation.
- **Approved for generating and verifying signatures: RSA, ECDSA and
  EdDSA.** DSA is retained **for verifying existing signatures only**.
- Recommended elliptic curves are in **NIST SP 800-186** (2023): the
  previously recommended Weierstrass curves over prime and binary fields,
  plus two new Edwards curves for EdDSA. The SP 800-186 page does not name
  the curves.
- Key sizes, hash pairings and curve names were not read (OPEN-SB-1).

## 2. X.509 certificates: RFC 5280

### 2.1 Structure (§4.1)

- A certificate is a signed body plus a signature algorithm identifier and
  the signature. The outer and inner algorithm identifiers must match.
- Version 3 is required when extensions are present.
- Serial numbers are unique per issuer and at most 20 octets.
- **Validity** (§4.1.2.5) is inclusive at both ends. Dates up to 2049 use
  UTCTime and from 2050 GeneralizedTime; both must be accepted. Times are
  UTC with seconds. 99991231235959Z means no defined expiry.
- If identity is only in the subject alternative name, the subject is
  empty and that extension is critical (§4.1.2.6).

### 2.2 Extensions (§4.2)

- An extension appears at most once. **A certificate with an unrecognised
  critical extension, or one that cannot be processed, must be
  rejected.** Unrecognised non-critical extensions may be ignored.
- Implementations must recognise key usage, certificate policies, subject
  alternative name, basic constraints, name constraints, policy
  constraints, extended key usage and inhibit anyPolicy.
- **Key usage** (§4.2.1.3): if present, a key may sign certificates or
  CRLs only with the matching bit; keyCertSign requires the CA flag.
- **Basic constraints** (§4.2.1.9): the CA flag says whether the key may
  verify certificate signatures. The path length limit applies only to CA
  certificates. CA certificates that sign certificates must carry this
  extension, marked critical.
- **Name constraints** (§4.2.1.10): only in CA certificates, critical,
  never empty. They limit names in later certificates of the path.
- **Extended key usage** (§4.2.1.12): if present, the certificate may be
  used only for the listed purposes, consistent with key usage too.
  `id-kp-serverAuth` is TLS server authentication; `id-kp-clientAuth` is
  TLS client authentication.
- **Subject alternative name** (§4.2.1.6): the CA must verify every name
  it binds.
- **CRL distribution points** (§4.2.1.13): where to fetch CRLs; HTTP
  locations hold one DER-encoded CRL.
- **Authority information access** (§4.2.2.1): non-critical; locations of
  the issuer's certificates and of an OCSP responder.

### 2.3 Path validation (§6.1) and revocation (§5, §6.3)

- Inputs: the candidate path, the current time, acceptable policies, and
  the trust anchor (name and public key), plus policy and name-constraint
  settings.
- For each certificate: verify the signature with the previous working
  key, check the validity period, check revocation, check the issuer name
  chains to the previous subject, and apply name constraints and
  policies. A failure ends validation.
- Between certificates: intermediates must be CA certificates (version 3
  with basic constraints and the CA flag), the path length limit is
  enforced, keyCertSign is checked when key usage is present, and
  critical extensions are processed.
- On success the output is the policy tree and the end certificate's
  public key.
- CRLs (§5): conforming CRLs are version 2 with next-update time, CRL
  number and authority key identifier. A CRL with a critical extension the
  application cannot process must not be used. Revocation checking (§6.3)
  works through the distribution points and yields revoked, not revoked,
  or undetermined.

## 3. Key management: NIST SP 800-57 Part 1 Rev. 5 [primary not read]

From NIST's publication page (May 2020, supersedes Rev. 4): general
guidance on managing cryptographic keys, covering the security services
cryptography can provide, the algorithms and key types available, how
each key type should be protected, key-management functions, and related
issues. Part 2 covers agency policy and planning; Part 3 covers specific
systems.

Cryptoperiods, key-type tables and protection requirements were not read
(OPEN-SB-2).

Related: NIST SP 800-131A Rev. 2 (March 2019) covers transitions to
stronger algorithms and key lengths. A draft Rev. 3 was put out for
comment in late 2024. Neither text was read.

## 4. Operator authentication options

### 4.1 PIV (FIPS 201-3; SP 800-73-5) [primary not read]

- FIPS 201-3 (January 2022) defines the Personal Identity Verification
  system for federal employees and contractors under HSPD-12: secure
  federal identity credentials used to authenticate people to federal
  facilities, information systems and applications, with identity
  proofing, interoperable credential infrastructure and accreditation of
  issuers. Derived PIV credentials and federation are in scope.
- SP 800-73-5 Part 1 (July 2024) specifies how to talk to the PIV card:
  a data model, a card-edge interface and a programming interface, with
  constraints on smart-card standard options for interoperability. Parts
  2 and 3 complete it.

### 4.2 Authenticator assurance (SP 800-63B, 2025 revision)

Read from NIST's HTML edition (page dated 2025-08-26; it supersedes the
earlier SP 800-63B).

| Level | Factors | Phishing resistance | Reauthentication | FIPS 140 |
|-------|---------|---------------------|------------------|----------|
| AAL1 (§2.1) | single or multi-factor | not required; multi-factor should be offered | overall timeout should be ≤ 30 days | federal verifiers Level 1 |
| AAL2 (§2.2) | two factors, or one multi-factor authenticator; at least one replay-resistant | must be offered; **federal agencies must require it for their staff, contractors and partners** | overall ≤ 24 h; inactivity ≤ 1 h | federal authenticators and verifiers Level 1 |
| AAL3 (§2.3) | cryptographic authenticator with a non-exportable private key (multi-factor, or single-factor plus password or biometric) | required | overall ≤ 12 h; inactivity ≤ 15 min | authenticators and verifiers Level 1 or higher |

- **Phishing resistance** (§3.2.5, formerly "verifier impersonation
  resistance") needs a cryptographic authenticator and either channel
  binding or verifier-name binding. One-time codes and out-of-band
  methods are not phishing-resistant. Keys must give at least 112 bits of
  security strength.
- The page states that PIV and CAC cards used with **client-authenticated
  TLS** are phishing-resistant through channel binding (§3.2.5).
- Syncable authenticators must not be used at AAL3.

### 4.3 Relevance

Background for the open decision on how operators authenticate
(`specs/operator-access.md` OPEN-ACC-1). Mutual TLS with operator
certificates (§2 and `http-tls.md` §6.3), including PIV/CAC certificates,
is one option the standards describe. This file does not choose.

## 5. Open questions

- **OPEN-SB-1**: FIPS 186-5 key sizes, hash pairings and the SP 800-186
  curve names need the primary texts.
- **OPEN-SB-2**: SP 800-57 Part 1 cryptoperiods and key-type guidance
  need the primary text.
- **OPEN-SB-3**: SP 800-131A Rev. 2 (and the Rev. 3 draft) transition
  rules, for example the status of SHA-1, need the primary text.
