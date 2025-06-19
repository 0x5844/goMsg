### 🔒 Security Architecture
#### Cryptographic Features
Key Exchange: Kyber1024 (post-quantum KEM) - quantum-resistant key encapsulation

Symmetric Encryption: XChaCha20-Poly1305 AEAD for authenticated encryption

Key Derivation: HKDF-SHA256 for deriving session keys from shared secrets

Authentication: HMAC-SHA256 for message integrity and authenticity

Transport: Tor v3 onion services for network anonymity

#### Memory Protection
Critical data stored in locked memory pages - prevents swapping to disk

Multi-pass secure wiping of sensitive variables - overwrites memory multiple times

Protected key structures with automatic cleanup - secure key lifecycle management

Runtime memory barriers prevent optimization attacks - prevents compiler optimizations that could leak data

#### Network Protection
All traffic routed through Tor - ensures network-level anonymity

Dynamic message padding (128-8192 bytes) - obscures message sizes

Timing jitter (0-500ms random delays) - prevents timing correlation attacks

Dummy traffic generation every 15 seconds - hides communication patterns

Automatic circuit rotation every 5 minutes - prevents long-term traffic analysis

### 🚀 Features
Anonymous P2P Messaging: Direct encrypted communication between peers

Post-Quantum Security: Resistance against quantum computer attacks

Friend Management: Add, approve, and manage trusted contacts with verification

QR Code Support: Easy onion address sharing and scanning

Broadcast Messages: Send messages to all online friends simultaneously

Fingerprint Verification: Out-of-band identity verification system

Key Rotation: Automatic and manual cryptographic key rotation

Traffic Analysis Resistance: Advanced techniques to hide communication metadata

Cross-Platform: Supports Linux, macOS, and Windows

#### Clone the repository
```
git clone https://github.com/0x5844/goMsg.git
cd goMsg
```
#### Install dependencies
```
go mod init goMsg
go mod tidy
```
#### Build the application
```
go build -o goMsg main.go
```
# Run with your username
```
./goMsg --user alice
```
or
# Install dependencies
```
go mod init pmessenger
go get github.com/Baozisoftware/qrcode-terminal-go
go get github.com/cloudflare/circl/kem/kyber/kyber1024
go get github.com/cretz/bine/tor
go get github.com/liyue201/goqr
go get github.com/spf13/pflag
go get github.com/spf13/viper
go get golang.org/x/crypto/chacha20poly1305
go get golang.org/x/crypto/hkdf
```
# Run directly
```
go run main.go --user alice
```
| Command                    | Description                           | Example                       |
|----------------------------|---------------------------------------|-------------------------------|
| /add <onion> <nickname>    | Add a friend by onion address         | /add abc123...xyz.onion alice |
| /approve <nickname>        | Approve a friend request              | /approve alice                |
| /friends                   | List all friends and their status     | /friends                      |
| /remove <nickname>         | Remove a friend                       | /remove alice                 |
| /chat <nickname> <message> | Send private message                  | /chat alice Hello!            |
| /broadcast <message>       | Send to all online friends            | /broadcast Good morning!      |
| /rotate <nickname>         | Force key rotation with friend        | /rotate alice                 |
| /fingerprint <nickname>    | Show verification fingerprints        | /fingerprint alice            |
| /qr                        | Display your onion address as QR code | /qr                           |
| /code <qr_data>            | Add friend from QR code data          | /code abc123...xyz.onion      |
| /quit                      | Exit application safely               | /quit                         |
