# Patronus Protocol Specification (v1.0)

**Abstract**
This document specifies the Patronus Protocol, a peer-to-peer (P2P) encryption and identity framework designed for decentralized communication. The protocol utilizes raw UDP/TCP sockets for transport and discovery, and employs modern cryptographic primitives to ensure end-to-end security, forward secrecy, and deterministic identity verification. As of now, Patronus, is meant to be used for local networks only.

---

## 1. Introduction
The Patronus Protocol provides a secure, serverless communication channel between nodes. It is designed to operate in various network environments, including local area networks (LAN) via mDNS and wide area networks via global rendezvous services.

### 1.1 Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174].

### 1.2 Node Identity
Each node MUST generate a static, long-term Ed25519 keypair upon initialization.
- **Static Public Key ($PK_{static}$):** The node's permanent identity.
- **NodeID:** Defined as the SHA-256 hash of the node's $PK_{static}$.
- **Persistence:** Nodes MUST securely store their static keypair. Loss of the private key results in a permanent loss of identity and trust.

---

## 2. Node Discovery and Rendezvous
Nodes MUST implement a multi-layered discovery strategy to facilitate peer-to-peer connectivity.

### 2.1 Local Discovery (UDP Broadcast)
Nodes on a shared broadcast domain MUST utilize UDP broadcast for local peer discovery.
- **Discovery Port:** `8888`
- **Payload Format:** `PATRONUSv<VERSION>|<APP_PORT>|<NODE_ID>`
    - `VERSION`: The current package version, fully quialified semver version.
    - `APP_PORT`: The port on which the node is listening.
    - `NODE_ID`: The node's unique identifier.
- **Announcement:** Nodes SHOULD broadcast their discovery payload every 3 seconds.

Every client can receive these packets even if they're not broadcasting their own, only clients wishing to initiate a connection SHOULD respond to the received packets.

### 2.2 Node Metadata
In the current implementation, basic metadata (Version, App Port, and NodeID) is encapsulated directly in the broadcast payload. Future versions MAY extend this using additional pipe-delimited fields or JSON payloads.

---

## 3. Cryptographic Primitives
The protocol specifies the following cryptographic primitives:

| Component | Primitive | Reference |
| :--- | :--- | :--- |
| Node Identity | Ed25519 (Signatures) | RFC 8032 |
| Key Exchange | X25519 (ECDH) | RFC 7748 |
| Authenticated Encryption | AES-256-GCM | NIST SP 800-38D |
| Key Derivation | HKDF-SHA256 | RFC 5869 |
| Message Digest | SHA-256 | FIPS 180-4 |
| Entropy Source | OS-provided CSPRNG | - |
| Nonce Construction | 96-bit random | - |

---

## 4. Handshake and Key Derivation (KDF)
Every session MUST begin with an ephemeral-ephemeral Diffie-Hellman exchange to establish a shared secret.

### 4.1 Ephemeral Key Exchange
Every 1:1 session MUST bind its ephemeral keys to the nodes' static identities to prevent impersonation.
1. Node A generates an ephemeral X25519 key pair $(sk_A, pk_A)$.
2. Node A computes a signature $\sigma_A = Sign(SK_{static\_A}, b"patronus-handshake-v1" || pk_A)$.
3. Node A transmits $pk_A$, $\sigma_A$, and its static public key $PK_{static\_A}$ to Node B.
4. Node B verifies that $SHA256(PK_{static\_A})$ matches the expected `NodeID` and validates $\sigma_A$ using $PK_{static\_A}$.
5. Node B repeats this process, transmitting its own $(pk_B, \sigma_B, PK_{static\_B})$.
6. Both nodes compute the shared secret $S = X25519(sk_{local}, pk_{remote})$.

### 4.2 Key Material Extraction
Nodes MUST use HKDF-SHA256 to derive session keys from the shared secret $S$.
- **Salt:** `b"patronus-protocol-v1"`
- **K_enc (Encryption Key):** Derived using info string `b"session-encryption"`. Length: 32 bytes.
- **K_id (Identity Key):** Derived using info string `b"identity-projection"`. Length: 3 bytes.

---

## 5. Deterministic Identity Projection
To mitigate Man-In-The-Middle (MITM) attacks, nodes MUST implement the Patronus Identity verification process.

### 5.1 Wordlist Requirements
The implementation MUST utilize three distinct wordlists (Adjectives, Colors, Spirits), each containing exactly 256 unique entries. The authoritative wordlists for the Patronus Protocol are defined in the `assets/wordlists.json` file in the reference implementation.

### 5.2 Derivation Flow
The identity phrase is constructed using the 3-byte `K_id`:
1. `Word[0] = ADJECTIVES[K_id[0]]`
2. `Word[1] = COLORS[K_id[1]]`
3. `Word[2] = SPIRITS[K_id[2]]`

The resulting phrase MUST be displayed to the user for out-of-band verification.
*Example Output: "Brave Crimson Stag"*

---

## 6. Wire Format and Framing

### 6.1 Handshake Packet
Initial public key exchange and feature negotiation MUST be encapsulated in a JSON-encoded gossip message. The JSON payload MUST be prepended with a 2-byte Big Endian unsigned integer specifying the byte length of the JSON string.
```json
{
  "type": "handshake",
  "pk": "<base64_encoded_ephemeral_x25519_public_key>",
  "spk": "<base64_encoded_static_ed25519_public_key>",
  "sig": "<base64_encoded_ed25519_signature_of_pk>",
  "extensions": ["compression:zstd", "ratchet:v1"]
}
```
The `extensions` array is REQUIRED and MUST contain at least one supported compression algorithm.

### 6.2 Message Schema

Once client handshake exchange completes, the message on the wire MUST conform to the following schema:
1. **Message Type**: 1 byte (specyfing the type of the message)
2. **Payload:** Variable length data specific to the Message Type.

The patronus specifies and acknowledges the folowing message types:
    - `0x01`: Application Message (UTF-8 encoded JSON).
    - `0x02`: Control Frame (Lifecycle management).
    - `0x03`: Extension Data (e.g., File chunks).

### 6.2 Application Message format
Authenticated messages MUST follow this binary structure:
1. **Frame Length:** 2 bytes (Big Endian unsigned integer specifying the combined length of the Ciphertext and Authentication Tag).
2. **Nonce:** 12 bytes (MUST be unique per message).
3. **Ciphertext:** Variable length (Compressed and Encrypted).
4. **Authentication Tag:** 16 bytes.

### 6.4 Additional Authenticated Data (AAD)
The AAD for the AES-GCM operation MUST be constructed as:
`AAD = b"patronus/1.0" || <32_byte_topic_id>`

Decryption MUST fail if the `topic_id` in the AAD does not match the active session. To prevent protocol downgrade attacks, future versions of this protocol MUST increment the version string in the AAD (e.g., `b"patronus/2.0"`) to ensure that messages from different protocol versions remain cryptographically distinct and incompatible.

---

## 7. Protocol Extensions (Advanced Arcanum)

### 7.1 Forward Secrecy (Time-Turner Ratchet)

If supported, nodes MUST derive two keys based on the role of the client, which are independent of each other.

Receiver expansion: `session-encryption-i2r`, which is used to encrypt messages sent to receiver.
Sender expansion: `session-encryption-r2i`, which is used to decrypt messages received from the sender.

Communication in Patronus is full duplex, so these two keys MUST be stored across all duration of session.

#### 7.1.1 Message modification

Message type of `0x01` are modified to acomodate the ratchet index, as shown below.

Rachet binary message format:
1. **Frame Length:** 2 bytes (Big Endian unsigned integer specifying the combined length of the Ciphertext and Authentication Tag).
2. **Rachet index:** 4 bytes (Big Endian unsigned integer specyfying the index of a key needed to decrypt the message)
2. **Nonce:** 12 bytes (MUST be unique per message).
3. **Ciphertext:** Variable length (Compressed and Encrypted).
4. **Authentication Tag:** 16 bytes.

Rachet indexes move only forward, if the message is received containg the index smaller than the one received in the last message, the incoming message are declared stale and MUST be discarded.

To mitigate a possibility of DOS attacks on applications implementing the Patronus protocol, maximum difference between the following indexes MUST be less or equal to 50. If the index difference is above the specified threshold, the connection MUST be severed.

### 7.2 Binary Stream Transfer (Owl Post)
Large data transfers SHOULD bypass the gossip channel in favor of direct QUIC streams.
- **Offer:** Sender MUST dispatch a `file-offer` JSON containing `file_name`, `size`, and a BLAKE3 `merkle_root`.
- **Encryption:** A unique sub-key MUST be derived for the transfer: `K_file = HKDF(K_enc, file_id)`.
- **Framing:** Data MUST be fragmented into 16KB chunks, each independently encrypted.

### 7.3 Ephemeral Messaging (Vanishing Ink)
Messages MAY include a `ttl` (Time-To-Live) field.
- **Enforcement:** Receivers MUST delete the message data from local storage once `current_time > arrival_time + ttl`.

### 7.4 Stealth Discovery (Invisibility Cloak)
To prevent passive identification, nodes MAY utilize rotating discovery hashes.
- **Hash:** `DiscoveryHash = BLAKE3(NodeID || DailySalt)`.
- **Resolution:** Nodes MUST pre-compute hashes for known contacts to identify peers without revealing `NodeID`s to unauthorized observers.

### 7.5 Message Compression (The Reducio Charm)
To optimize bandwidth utilization and improve protocol efficiency, nodes MUST implement and utilize transparent payload compression.

#### 7.5.1 Negotiation
Compression MUST be negotiated during the initial handshake (Section 6.1).
- **Advertisement:** Nodes MUST include at least one string in the format `"compression:<alg>"` in the `extensions` array.
- **Agreement:** A common algorithm MUST be selected. If peers fail to agree on a compression algorithm, the connection MUST be terminated. In Active Mode, the first algorithm in the initiator's list that is also present in the responder's list SHALL be selected.

#### 7.5.2 Operation
- **Algorithm:** The default REQUIRED algorithm is Zstandard (zstd) [RFC8878], identified as `"compression:zstd"`.
- **Processing Order:** Compression MUST be applied to the plaintext payload *before* the authenticated encryption process (Section 6.2).
- **Security:** Implementations MUST be wary of compression-ratio side channels (e.g., CRIME/BREACH style attacks) when compressing sensitive data with known patterns.

---

## 8. Session Lifecycle and Control

### 8.1 Lifecycle Management
Nodes MUST manage the active state of established connections using Control Frames (`0x02`).

### 8.2 Keep-Alives (The Lumos Pulse)
To maintain connectivity through NATs and detect silent drops, nodes SHOULD implement application-layer keep-alives.
- **Interval:** During periods of inactivity, a node SHOULD transmit a PING frame every 15 seconds.
- **Ping:** A node sends a `0x02` frame with a 1-byte `PING` payload (`0x01`).
- **Pong:** Upon receiving a `PING`, a node MUST immediately respond with a `PONG` payload (`0x02`).
- **Timeout:** If no `PONG` is received within 30 seconds of a `PING`, the connection SHOULD be considered dropped.

### 8.3 Graceful Closure
Nodes SHOULD notify peers before disconnecting to ensure a clean session termination.
- **Disconnect Frame:** A node sends a `0x02` frame with a `BYE` payload (`0x03`).
- **Termination:** Upon sending or receiving a `BYE` frame, nodes MUST cease transmission and close the underlying transport.

### 8.4 Error Signaling
Protocol-level errors MUST be signaled using a `0x02` frame followed by a 1-byte error code.
- **0x01 (Handshake Failed):** Peers could not agree on extensions or compression.
- **0x02 (Invalid Ratchet):** Received a message with an unrecoverable `ratchet_index`.
- **0x03 (Security Violation):** AAD mismatch or decryption failure detected.

---

## 9. Security Considerations and Trust Model

### 9.1 Trust-On-First-Use (TOFU)
Implementations MUST persist verified `NodeID` and `Identity` mappings.
- **Verification:** On subsequent connections, the implementation MUST verify the derived identity against the stored value.
- **Alerting:** If an identity mismatch occurs for a known `NodeID`, the implementation MUST terminate the connection and alert the user of a potential MITM attack.

### 9.2 Cryptographic Boundaries
All cryptographic operations MUST be performed using constant-time implementations where applicable to prevent side-channel leakage.
