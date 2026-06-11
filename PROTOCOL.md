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
- **Static Public Key ($PK_{static}$):** The node's permanent identity (32 bytes).
- **NodeID:** Defined as the standard Base64 representation of the SHA-256 hash of the node's $PK_{static}$.
- **Persistence:** Nodes MUST securely store their static keypair. Loss of the private key results in a permanent loss of identity and trust.

---

## 2. Node Discovery and Rendezvous
Nodes MUST implement a multi-layered discovery strategy to facilitate peer-to-peer connectivity.

### 2.1 Local Discovery (UDP Broadcast)
Nodes on a shared broadcast domain MUST utilize UDP broadcast for local peer discovery.
- **Discovery Port:** `8888`
- **Payload Format:** `PATRONUSv<VERSION>|<APP_PORT>|<NODE_ID>`
    - `VERSION`: The current package version, fully qualified semver version.
    - `APP_PORT`: The port on which the node is listening.
    - `NODE_ID`: The node's unique identifier (Base64 encoded SHA-256 hash of $PK_{static}$).
- **Announcement:** Nodes SHOULD broadcast their discovery payload every 3 seconds.

Every client can receive these packets even if they're not broadcasting their own. Only clients wishing to initiate a connection SHOULD respond to the received packets by establishing a TCP connection to the sender's `APP_PORT`.

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
- **K_i2r (Initiator→Responder Encryption Key):** Derived using info string `b"session-encryption-i2r"`. Length: 32 bytes.
- **K_r2i (Responder→Initiator Encryption Key):** Derived using info string `b"session-encryption-r2i"`. Length: 32 bytes.
- **K_id (Identity Key):** Derived using info string `b"identity-projection"`. Length: 3 bytes.

Directional key assignment MUST be performed as follows:
- The **initiator** MUST use $K_{i2r}$ as its send key and $K_{r2i}$ as its receive key.
- The **responder** MUST use $K_{r2i}$ as its send key and $K_{i2r}$ as its receive key.

This directional split ensures that each side maintains an independent ratchet chain (Section 7.1), preventing key state divergence when both nodes transmit concurrently.

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

### 6.2 Message Framing and Wire Format

Once the handshake exchange completes, all post-handshake packets (including Application Messages `0x01`, Control Frames `0x02`, and Extension Data `0x03` - except for raw file chunks, which have a modified framing described in Section 7.2) transmitted over the TCP stream MUST conform to a unified wire format.

Each frame consists of the following contiguous fields:
1. **Frame Length:** 4 bytes (Big Endian unsigned 32-bit integer, specifying the length of the Ciphertext and Authentication Tag in bytes).
2. **Ratchet Index:** 4 bytes (Big Endian unsigned 32-bit integer, representing the key ratchet index).
3. **Nonce:** 12 bytes (randomly generated initialization vector, unique per message).
4. **Encrypted Payload (Ciphertext + Authentication Tag):** Variable length (equal to Frame Length).

### 6.3 Plaintext Payload Format

Before compression and encryption (and after decryption and decompression), the plaintext payload MUST conform to the following schema:
1. **Message Type:** 1 byte specifying the category of the message:
    - `0x01`: Application Message (UTF-8 encoded JSON).
    - `0x02`: Control Frame (Session lifecycle management).
    - `0x03`: Extension Data (e.g., File transfer metadata, TTL notices).
2. **Payload:** Variable-length data specific to the Message Type.

If compression (Section 7.5) was negotiated during the handshake, the entire plaintext payload (including the 1-byte Message Type) MUST be compressed first, then encrypted.

### 6.4 Additional Authenticated Data (AAD) and Topic ID Derivation

The Additional Authenticated Data (AAD) input for the AES-256-GCM operation MUST be constructed as:
`AAD = b"patronus/1.0" || <32_byte_topic_id>`

#### 6.4.1 Topic ID Derivation
The `topic_id` is a unique 32-byte identifier derived from the static identities of the two participating nodes to bind the session cryptographically. It is computed as:
1. Sort the static public keys of the two nodes byte-wise (lexicographically ascending).
2. Compute the SHA-256 hash of the concatenated 32-byte public keys:
   $$topic\_id = SHA256(min(PK_{static\_A}, PK_{static\_B}) \mathbin{\Vert} max(PK_{static\_A}, PK_{static\_B}))$$

Decryption MUST fail if the `topic_id` in the AAD does not match the active session. To prevent protocol downgrade attacks, future versions of this protocol MUST increment the version string in the AAD (e.g., `b"patronus/2.0"`) to ensure that messages from different protocol versions remain cryptographically distinct and incompatible.

---

## 7. Protocol Extensions (Advanced Arcanum)

### 7.1 Forward Secrecy (Time-Turner Ratchet)

If supported (negotiated via `"ratchet:v1"` extension during the handshake), nodes MUST derive two directional keys based on the role of the client (Initiator or Responder), which are independent of each other.

- **Initiator:** Uses $K_{i2r}$ (derived via info `b"session-encryption-i2r"`) to encrypt messages sent to the responder, and $K_{r2i}$ (derived via info `b"session-encryption-r2i"`) to decrypt messages received from the responder.
- **Responder:** Uses $K_{r2i}$ to encrypt messages sent to the initiator, and $K_{i2r}$ to decrypt messages received from the initiator.

Communication in Patronus is full duplex, so both independent keys MUST be persisted for the duration of the session.

#### 7.1.1 Key Advancement (Ratchet Step)
Each time a message is sent, the sender's encryption key is advanced. Similarly, when a message is received, the receiver's decryption key is advanced to match the incoming `Ratchet Index`.

The key advancement function is defined as:
$$K_{next} = HKDF\_SHA256(IKM = K_{current}, Salt = None, Info = b"time-turner-ratchet", Length = 32)$$

#### 7.1.2 Ratchet Index Validation
The `Ratchet Index` starts at `0`.
- On every message sent: The local ratchet index is incremented by 1, and the key is advanced by one step. The updated index is sent in the `Ratchet Index` field of the wire frame (Section 6.2).
- On every message received: The receiver extracts the `remote_ratchet` index from the wire frame.
  - If `remote_ratchet <= ratchet_recv` (less than or equal to the last received ratchet index), the message is considered stale or replayed and MUST be discarded.
  - The receiver computes the index difference: $steps = remote\_ratchet - ratchet\_recv$.
  - To mitigate denial-of-service (DoS) attacks (e.g., preventing the CPU from executing endless ratchet steps if a massive index is sent), the index difference MUST be less than or equal to `50` ($steps \le 50$). If the index difference exceeds this threshold, the connection MUST be severed.
  - The receiver advances their decryption key $steps$ times using the key advancement function, decrypts the message, and updates the stored key and $ratchet\_recv = remote\_ratchet$.

### 7.2 Binary Stream Transfer (Owl Post)

If supported (negotiated via `"owl-post:v1"` extension during the handshake), large data transfers (such as files) can be initiated. Instead of direct QUIC streams, file transfers are multiplexed over the existing TCP session using Extension Data (`0x03`) frames.

#### 7.2.1 Key Derivation for File Transfers
To secure the file transfer, a unique file-specific sub-key $K_{file}$ MUST be derived by both nodes. This ensures that even if session keys are compromised, file transfers remain protected, and vice versa.

The file key derivation function is defined as:
$$K_{file} = HKDF\_SHA256(IKM = merkle\_root\_hex, Salt = topic\_id, Info = b"owl-post-file-key", Length = 32)$$

Where:
- `merkle_root_hex` is the UTF-8 representation of the file's hex-encoded BLAKE3 Merkle root.
- `topic_id` is the 32-byte session topic ID (Section 6.4.1).

#### 7.2.2 Control Flow and Negotiation
Before file chunks are transmitted, the transfer MUST be negotiated using JSON payloads wrapped in Extension Data (`0x03`) frames.

1. **File Offer:** The sender offers a file by sending a JSON payload:
   ```json
   {
     "file_offer": {
       "file_name": "<string>",
       "size": <u64_size_in_bytes>,
       "merkle_root": "<blake3_merkle_root_hex>"
     }
   }
   ```
2. **File Acceptance:** If the receiver accepts, they send a JSON payload. This payload includes an optional `start_offset` to allow resuming partially downloaded files:
   ```json
   {
     "file_accept": {
       "merkle_root": "<blake3_merkle_root_hex>",
       "start_offset": <u64_offset_or_null>
     }
   }
   ```
3. **File Decline:** If the receiver declines the offer, they send:
   ```json
   {
     "file_decline": {
       "merkle_root": "<blake3_merkle_root_hex>"
     }
   }
   ```

#### 7.2.3 Data Chunk Framing and Transmission
Once the file offer is accepted, the sender fragments the file into chunks (default size is 1MB, but it can be smaller/variable, and there can be optional millisecond delays between chunks).

Each chunk is processed and sent as follows:
- **No Compression:** To avoid CPU bottlenecking during transfer, compression MUST NOT be applied to file chunks.
- **Plaintext Format:** The plaintext before encryption is a 1-byte Message Type `0x03` followed by the raw bytes of the file chunk.
- **Encryption:** The plaintext is encrypted using AES-256-GCM with the derived $K_{file}$ key. The AAD is the same as the session AAD (Section 6.4).
- **Wire Frame:** The encrypted chunk is sent over the TCP stream with a modified wire frame:
  1. **Frame Length:** 4 bytes (Big Endian `u32` of the Ciphertext + Tag length).
  2. **Sentinel/Ratchet Index:** 4 bytes (fixed value `0xFFFFFFFF` to indicate this is a non-ratchet file chunk).
  3. **Nonce:** 12 bytes.
  4. **Ciphertext + Auth Tag:** Variable length.

#### 7.2.4 Partial Transfer Resuming
The receiver can check if a file with the same name already exists in their download directory. If the local file length is smaller than the offered size, the receiver can send the local file length as `start_offset` in the `file_accept` message. The sender MUST seek to that offset in the source file and begin transmission from there.

### 7.3 Ephemeral Messaging (Vanishing Ink)
The protocol supports ephemeral messaging through the use of a Time-To-Live (TTL) mechanism. This feature allows nodes to specify a duration after which a message should be considered expired. To facilitate exchange of TTL settings between peers, nodes MAY implement the `vanishing_ink` extension.

#### 7.3.1 Extension negotiation
- **Negotiation:** Support for this feature MUST be advertised during the handshake (Section 6.1) by including the string `"vanishing_ink:v1"` in the `extensions` array.
- **Requirements:** A node MUST NOT include the `ttl` field and MUST NOT transmit TTL notices unless the `vanishing_ink` extension has been mutually negotiated.

#### 7.3.2 TTL Field in Application Messages
Application Messages (`0x01`) MAY include a `ttl` field within the JSON-encoded payload.
- **Field Name:** `ttl`
- **Type:** Unsigned Integer (seconds)
- **Enforcement:** Receivers MUST delete the message data from local storage once `current_time > arrival_time + ttl`.

#### 7.3.3 TTL Notices
When the `vanishing_ink:v1` extension is active, a node SHOULD notify its peer whenever its default outgoing TTL setting changes. This is performed using an Extension Data frame (`0x03`).

The payload of the Extension Data frame MUST be a JSON-encoded object with the following structure:
```json
{
  "ttl_notice": <u64_or_null>
}
```
- **ttl_notice:** The new TTL value in seconds, or `null` if TTL is being disabled.

Upon receiving a valid `ttl_notice`, the implementation SHOULD update the user interface to reflect the peer's current ephemeral messaging status.

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
Protocol-level errors are defined as:
- **0x01 (Handshake Failed):** Peers could not agree on extensions or compression.
- **0x02 (Invalid Ratchet):** Received a message with an unrecoverable `ratchet_index`.
- **0x03 (Security Violation):** AAD mismatch or decryption failure detected.

> [!NOTE]
> While the protocol specifies sending a `0x02` control frame followed by a 1-byte error code to signal these conditions, the reference client implementation does not transmit or handle these codes. Instead, the connection is immediately terminated when any protocol-level error or decryption failure occurs.

---

## 9. Security Considerations and Trust Model

### 9.1 Trust-On-First-Use (TOFU)
Implementations MUST persist verified `NodeID` and `Identity` mappings.
- **Verification:** On subsequent connections, the implementation MUST verify the derived identity against the stored value.
- **Alerting:** If an identity mismatch occurs for a known `NodeID`, the implementation MUST terminate the connection and alert the user of a potential MITM attack.

### 9.2 Cryptographic Boundaries
All cryptographic operations MUST be performed using constant-time implementations where applicable to prevent side-channel leakage.
