## Product description
Mongoose is an embedded networking library written in portable C. It
provides HTTP/1.1, HTTP/2, WebSocket, MQTT, CoAP, mDNS/DNS, and TLS
(built-in or OpenSSL-backed) in a single-source-file build, targeted at
firmware engineers running on resource-constrained devices as well as
general-purpose Linux/POSIX services.

## Critical assets
- TLS private keys, certificates, and the peer-certificate verification path
- Device credentials and session state in HTTP/MQTT/WebSocket connections
- Network message buffers (inbound parser state for HTTP, MQTT, WebSocket, mDNS) — corruption here is exploitable
- Listening sockets and per-connection state machines
- The filesystem the process has write access to (upload/static-file handlers)

## Users and roles
- firmware-developer: links Mongoose into device firmware; owns cert-loading and handler wiring
- end-user: interacts with the device through Mongoose-served HTTP/MQTT/WebSocket
- ota-update-service: external system publishing firmware via MQTT/HTTPS
- attacker-on-network: untrusted peer on the LAN or open internet with port reachability, no prior authentication

## Deployment
Mongoose ships as source; deployments are heterogeneous (resource-constrained
MCU running RTOS, Linux/POSIX edge gateway, standalone Linux binary). The
trust boundary is the network socket — HTTP, MQTT, WebSocket, and mDNS/DNS
traffic all arrive from untrusted peers before any application-level
authentication occurs.

## Threat actors of concern
- Remote unauthenticated network attacker sending malformed protocol input (parser corruption, DoS, info leak)
- Network-adjacent attacker exploiting mDNS/DNS-SD (no auth, UDP, LAN-broadcast reachable)
- TLS-handshake peer presenting a malicious certificate (client or server role)
- Authenticated MQTT/HTTP client abusing an exposed handler (e.g. file upload) beyond its intended scope
- Supply-chain: tampered mongoose.c amalgamation in a downstream build

## Out of scope
- Physical-tampering / side-channel attacks against silicon
- The linked TLS library's own threat model when OpenSSL/mbedTLS/BearSSL is used instead of Mongoose's built-in stack (only Mongoose's own glue code is in scope)
- Bugs introduced by an embedding application's misuse of the C API
