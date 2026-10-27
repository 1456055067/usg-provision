# Standards summary: HTTP semantics and TLS for content transfer

Topic 17 of the standards reading list. Our summary of the parts of RFC
9110 (HTTP semantics), RFC 8446 (TLS 1.3, now obsoleted by RFC 9846) and
NIST SP 800-52 Rev. 2 that matter for uploading and downloading content
(images, preinstall environments) and for operator sessions. Items marked
**(conditional)** relate to behaviour no source requires yet. Read them
only if the clean side or a recorded decision calls for them.

Labels: **[primary not read]** means the primary text could not be read
with the available tools and only the publisher's summary page was used.

## 1. Methods (RFC 9110 §9)

- **Safe** methods (no requested state change): GET, HEAD, OPTIONS, TRACE
  (§9.2.1).
- **Idempotent** methods (repeating has the same effect as once): PUT,
  DELETE and the safe methods (§9.2.2). Clients should not retry a
  non-idempotent request automatically unless they know it is safe;
  proxies must not.
- **GET** (§9.3.1) returns a current representation. A body in a GET
  request has no defined meaning. Range requests (§5) change GET.
- **HEAD** (§9.3.2): as GET without content; the server should send the
  same header fields.
- **POST** (§9.3.3): the target resource processes the enclosed data by
  its own rules. If it creates a resource, the server should answer 201
  with a `Location` field naming it.
- **PUT** (§9.3.4) creates or replaces the target's state. It must answer
  201 when it created the resource and 200 or 204 when it changed an
  existing one. The server should check the data against its rules (409
  or 415 when they fail).
- **DELETE** (§9.3.5): successful answers include 202, 204 and 200.

## 2. Message size and framing (RFC 9110 §5.4, §8.6, §15.5)

- A server receiving a header field or header section larger than it will
  process should answer with a 4xx status. Silently ignoring it risks
  request smuggling (§5.4).
- `Content-Length` (§8.6): a sender must not forward a message whose
  length is wrong or does not match the syntax. A repeated identical value
  in a list may be rejected or collapsed to one. 1xx and 204 responses,
  and 2xx responses to CONNECT, must not carry it.
- 411 Length Required (§15.5.12): the server needs a `Content-Length`.
- 413 Content Too Large (§15.5.14): the content is larger than the server
  will accept. `Retry-After` may say the condition is temporary.
- CR, LF or NUL in a field value: reject the message or replace them with
  spaces (§5.5).

## 3. Status codes used by content services (RFC 9110 §15)

| Code | Meaning | § |
|------|---------|---|
| 200 | OK; meaning depends on the method | 15.3.1 |
| 201 | Created; identified by `Location` or the target URI | 15.3.2 |
| 204 | No Content; success with nothing to return | 15.3.5 |
| 206 | Partial Content (conditional; §5) | 15.3.7 |
| 400 | Bad Request: malformed or invalid | 15.5.1 |
| 401 | Unauthorized: authentication needed or refused; must carry `WWW-Authenticate` | 15.5.2 |
| 403 | Forbidden: understood but refused | 15.5.4 |
| 404 | Not Found, or existence not disclosed | 15.5.5 |
| 405 | Method Not Allowed; must carry `Allow` | 15.5.6 |
| 409 | Conflict with the resource's current state | 15.5.10 |
| 411 | Length Required | 15.5.12 |
| 412 | Precondition Failed | 15.5.13 |
| 413 | Content Too Large | 15.5.14 |
| 415 | Unsupported Media Type or content coding | 15.5.16 |
| 416 | Range Not Satisfiable (conditional) | 15.5.17 |
| 422 | Unprocessable Content: syntax valid, instructions cannot be processed | 15.5.21 |
| 500 | Internal Server Error | 15.6.1 |
| 503 | Service Unavailable; may carry `Retry-After` | 15.6.4 |

## 4. Validators and conditional requests (RFC 9110 §8.8.3, §13)

- **Entity tags** (§8.8.3) are strong unless marked weak with `W/`. Strong
  comparison needs both tags strong and identical.
- **If-Match** (§13.1.1): proceed only if the current tag matches (strong
  comparison), or for `*` if a representation exists. Otherwise do not
  perform the method; 412 may be sent. Used to prevent lost updates when
  two clients change the same resource.
- **If-None-Match** (§13.1.2): proceed only if no tag matches (weak
  comparison), or for `*` if no representation exists. On failure: 304
  for GET or HEAD, 412 otherwise. `If-None-Match: *` stops a PUT from
  overwriting an existing resource.
- Evaluation order (§13.2.2): If-Match, If-Unmodified-Since,
  If-None-Match, If-Modified-Since, then If-Range.

## 5. (conditional) Range requests (RFC 9110 §14)

No source requires resumable transfers. Summarised for reference.

- Byte ranges are zero-based and inclusive. A missing or too-large last
  position means "to the end"; a suffix range means "the last N bytes". A
  range whose last position is before its first is invalid. Large numbers
  must not cause overflow (§14.1.1, §14.1.2).
- `Range` (§14.2) is defined only for GET. A server may ignore it, though
  origin servers should support byte ranges. A server may ignore or reject
  requests with many small, overlapping or unordered ranges; they can be a
  denial-of-service attempt (§17.15).
- `Accept-Ranges` (§14.3) advertises range support; `none` means none.
- `Content-Range` (§14.4) appears in 206 and 416 responses. Invalid values
  (last before first, or length not greater than last) must not be
  combined with stored data. A 416 uses the `*/length` form.
- `If-Range` (§13.1.5) lets a client with part of a representation ask for
  the rest only if it has not changed; otherwise it gets the whole thing.
  It must not be sent without `Range` or with a weak tag.
- **Partial PUT** (§14.5) is not standard HTTP. A server that does not
  support it should answer 400. Alternatives the RFC mentions: PATCH, or
  separate resources for the parts.

## 6. TLS 1.3 (RFC 8446; RFC 9846)

RFC 8446 is now **obsoleted by RFC 9846** (Proposed Standard, 2026),
which also obsoletes RFC 5246 (TLS 1.2). §6.6 lists the changes.

### 6.1 Handshake (RFC 8446 §2)

- Key exchange modes: (EC)DHE, PSK only, and PSK with (EC)DHE.
- ClientHello carries key shares, PSK offers and signature algorithms.
  ServerHello selects parameters and its key share. Everything after
  ServerHello is encrypted: EncryptedExtensions, optional
  CertificateRequest, Certificate, CertificateVerify, Finished.
- A HelloRetryRequest is sent when the client's key shares do not fit
  (§4.1.4).
- Application data waits for Finished, except 0-RTT data (6.4 below).

### 6.2 Version negotiation and downgrade protection (§4.1.3, §4.2.1)

- Versions are negotiated with the `supported_versions` extension; the
  legacy version field is ignored when it is present.
- A TLS 1.3 server that negotiates TLS 1.2 or lower puts a fixed marker in
  its random value; a TLS 1.3 client must check it and abort if found.
- Renegotiation is not allowed in TLS 1.3 (§4.1.2).

### 6.3 Client certificates (§4.3.2, §4.4.2 to §4.4.4, §4.6.2)

- The server asks with CertificateRequest. The client answers with
  Certificate, CertificateVerify and Finished.
- Post-handshake client authentication is possible only if the client
  advertised it in ClientHello.
- Certificate-based authentication requires the peer's
  `signature_algorithms` extension (§4.2.3).
- `security-baseline.md` §2 covers certificate validation; §4 covers PIV.

### 6.4 0-RTT (§2.3, §8, Appendix E.5)

Early data is not forward secret and has no replay protection across
connections. Servers must limit replay as described in §8.

### 6.5 Mandatory to implement (§9.1, §9.2, Appendix B.4)

- Cipher suite **TLS_AES_128_GCM_SHA256** {0x13,0x01} must be implemented;
  TLS_AES_256_GCM_SHA384 {0x13,0x02} and TLS_CHACHA20_POLY1305_SHA256
  {0x13,0x03} should be. Also defined: TLS_AES_128_CCM_SHA256 {0x13,0x04},
  TLS_AES_128_CCM_8_SHA256 {0x13,0x05}.
- Signatures that must be supported: rsa_pkcs1_sha256,
  rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256. Key exchange: secp256r1
  (P-256) required; X25519 recommended.
- Extensions that must be supported: supported_versions, cookie,
  signature_algorithms, signature_algorithms_cert, supported_groups,
  key_share, server_name. A ClientHello missing required extensions is
  aborted with `missing_extension`.
- Removed compared with TLS 1.2 (§1.2): static RSA and static DH key
  exchange (all key exchange is forward secret), non-AEAD ciphers,
  compression, DSA, custom DHE groups, renegotiation; RSA signatures in
  the handshake use RSASSA-PSS.

### 6.6 RFC 9846 changes from RFC 8446 (its own summary)

Key shares must not be reused across connections; TLS 1.0 and 1.1 must
not be negotiated; key updates before key-usage limits become a MUST and
KeyUpdate messages are limited; a generic `general_error` alert is added;
key exchange wording covers KEM-based exchange; the text requiring RSA PSS
is removed; several length bounds are corrected.

## 7. NIST SP 800-52 Rev. 2 (U.S. Government TLS) [primary not read]

From NIST's publication page (August 2019; under review in 2026):

- Guidance on selecting and configuring TLS using FIPS-based and
  NIST-recommended cryptography, including certificates and TLS
  extensions.
- U.S. Government TLS servers and clients **must support TLS 1.2**
  configured with FIPS-based cipher suites, and **must support TLS 1.3 by
  1 January 2024**.

The PDF text could not be extracted, so its cipher-suite lists,
certificate and key-size requirements, extension requirements and
client-authentication guidance are not summarised (OPEN-TLS-1).

## 8. Open questions

- **OPEN-TLS-1**: the detailed SP 800-52 Rev. 2 requirements (allowed
  TLS 1.2 and 1.3 cipher suites, certificate profile, mutual
  authentication guidance) need the primary text.
- **OPEN-TLS-2**: whether to follow RFC 9846 rather than RFC 8446 for new
  work. A clean-side decision.
