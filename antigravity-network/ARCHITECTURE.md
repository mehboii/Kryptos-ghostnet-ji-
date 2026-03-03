# Antigravity Network Architecture

## 1. System Overview
Antigravity is a decentralized, peer-to-peer (P2P) mesh platform designed to enable global communication and computation without reliance on central servers. It leverages a device-to-device (D2D) mesh architecture where every consumer device (phone, laptop, IoT) acts as a network node.

### Core Principles
- **Zero-Trust & Full Decentralization:** No authority nodes or central servers.
- **Privacy by Default:** Everything is End-to-End Encrypted (E2EE).
- **Censorship Resistance:** Adaptive routing circumvents blocking.
- **Offline-First:** Asynchronous store-and-forward capabilities.

---

## 2. Identity & Security (The Cryptographic Layer)
Unlike traditional web accounts, identity in Antigravity is purely cryptographic.

- **Identity Generation:** ECDSA (secp256k1) or Ed25519 keypairs. 
- **Node ID:** Derived from the Public Key (e.g., `Multihash(PubKey)`).
- **Trust Model:** 
  - **TOFU (Trust On First Use)** for new contacts.
  - **Reputation Scoring** based on signed interactions and packet forwarding reliability.
  - **Web of Trust** ring signatures for privacy-preserving verification.

---

## 3. Networking Stack via Libp2p/Noise

### 3.1 Local Discovery (Layer 0)
Nodes automatically discover peers in physical proximity.
- **Transports:**
  - Bluetooth Low Energy (BLE) for near-field low-power discovery.
  - Wi-Fi Direct (P2P) for high-bandwidth local transfer.
  - Local Multicast (mDNS) for LAN discovery.
  - LoRa (Optional) for long-range, low-bandwidth emergency bridging.

### 3.2 Global Overlay (Layer 1)
Local meshes bridge together to form the global network.
- **Bridge Nodes:** Nodes with active Internet connections act as intermittent bridges.
- **Dynamic Rotation:** No fixed gateways; bridge roles rotate to prevent IP blocking.
- **Transport Security:** The Noise Protocol Framework guarantees forward secrecy on all links.

---

## 4. Routing & Data Transport
The routing layer is hybrid, designed for high churn (mobile devices).

- **GossipSub:** For broadcasting real-time messages and routing table updates.
- **Kademlia DHT:** modified for mobile latency; used for locating specific content or user mailboxes.
- **Onion Routing:** Traffic is wrapped in layers of encryption. Intermediary nodes know only the previous hop and the next hop, not the source or destination.
- **Store-and-Forward (Delay Tolerant Networking):** 
  - If a destination is offline, encrypted packets are stored in the local mesh cloud.
  - When the user reconnects, nearby nodes deliver the "inbox".

---

## 5. Content Addressing & Storage
Data is not stored by location (URL) but by content (Hash).

- **IPFS-style DAGs:** Files are chunked, hashed (CID), and distributed.
- **Replication:**
  - **Hot Data:** Messages and active files are replicated partially across the local cluster.
  - **Cold Data:** Long-term storage uses erasure coding across stable nodes.
- **Garbage Collection:** Ephemeral content expires (TTL) unless pinned by the owner or community.

---

## 6. Services & Computation

### Messaging
- Signal-style double ratchet encryption.
- Offline delivery via mesh relay.

### Edge Compute
- Distributed task scheduler allows nodes to offload computation (e.g., image processing) to idle nearby nodes.
- Tasks are verified via probabilistic checking (randomly assigning the task to multiple nodes and comparing results).

### Consensus (The "Pulse")
- **No Global Blockchain:** A global ledger is too heavy for phones.
- **Cluster Consensus:** Local clusters use a lightweight DAG-based consensus (like IOTA or Nano) to order events/payments relative to each other.
- **Conflict Resolution:** Last-Write-Wins (LWW) for mutable data (CRDTs).

---

## 7. Implementation Strategy

### Phase 1: The Core (MVP)
- **Stack:** Rust (performance) or Go (simplicity). Wrapped in lightweight UI.
- **Focus:** Reliable BLE/WiFi discovery and basic text messaging.

### Phase 2: The Bridge
- Implement WASM web-nodes to allow browser-based ephemeral nodes.
- Enable Internet-bridging for cross-continent mesh linking.

### Phase 3: The Ecosystem
- API for third-party "dApps" providing storage, compute, and social feeds on top of Antigravity.
