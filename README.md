# ESP32 Secure Captive Portal Honeypot & Cryptographic Access Logger

An educational cybersecurity honeypot and proof-of-concept rogue access point built for the ESP32 microcontroller. The firmware demonstrates captive portal credential harvesting combined with an application-layer secure retrieval channel. While client credential submissions occur over plaintext HTTP (simulating typical public Wi-Fi behavior), administrative retrieval of logged credentials is authenticated and encrypted end-to-end via an ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange and AES-256-CBC cipher, preventing unauthorized eavesdropping on the open wireless medium.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Key Features](#key-features)
3. [Operational Workflow](#operational-workflow)
   - [Phase 1: Victim Connection & Captive Portal Redirection](#phase-1-victim-connection--captive-portal-redirection)
   - [Phase 2: Administrative ECDH Handshake & Encrypted Data Retrieval](#phase-2-administrative-ecdh-handshake--encrypted-data-retrieval)
4. [REST API Reference](#rest-api-reference)
   - [Captive Portal & Detection Probes](#captive-portal--detection-probes)
   - [Credential Harvesting API](#credential-harvesting-api)
   - [Cryptographic Handshake & Exfiltration API](#cryptographic-handshake--exfiltration-api)
4. [Data Storage & Concurrency Control](#data-storage--concurrency-control)
6. [Complete Decryption Client (Python)](#complete-decryption-client-python)
7. [Project File Structure](#project-file-structure)
8. [Build, Dependencies & Flashing](#build-dependencies--flashing)
9. [Legal & Ethical Disclaimer](#legal--ethical-disclaimer)

---

## Architecture Overview

Public Wi-Fi honeypots typically capture credentials in plaintext, but extracting harvested data often introduces security risks: transmitting logs over unencrypted HTTP exposes the captured credentials to any passive listener with a packet sniffer (e.g., Wireshark). 

This firmware solves that problem by implementing **Application-Layer Forward-Secure Encryption**:
- **Client Facing**: Acts as an unencrypted Access Point (AP) running a DNS capture server and an asynchronous web server (`ESPAsyncWebServer`) serving a simulated portal.
- **Administrative Channel**: Enables the operator to negotiate a dynamic symmetric session key on demand using ECDH and HKDF, retrieving the flash-stored logs inside an AES-256-CBC encrypted payload that is purged from flash memory immediately upon exfiltration.

```
                      +-----------------------------------+
                      |          ESP32 Firmware           |
                      |                                   |
                      |  +-----------------------------+  |
                      |  |     Async Web Server (80)   |  |
                      |  +-----------------------------+  |
                      |        |                 |        |
                      |        v                 v        |
                      |  [Captive Portal]  [Crypto Engine]|
                      |  [  Controller  ]  [  mbedTLS ]   |
                      |        |                 |        |
                      |        v                 v        |
                      |  [Access Repo] <--- [AES Cipher]  |
                      |  (FreeRTOS Mutex)                 |
                      |        |                          |
                      |        v                          |
                      |  [LittleFS: /log.csv]             |
                      +-----------------------------------+
                           ^                       ^
                           | (HTTP POST / Plain)   | (ECDH + AES Encrypted)
                           |                       |
               +--------------------+    +--------------------+
               |    Target Client   |    |    Administrator   |
               | (Victim Device)    |    | (Operator Client)  |
               +--------------------+    +--------------------+
```

---

## Key Features

- **Multi-Platform Captive Portal Detection**: Automatically triggers native captive portal detection prompts on Android, iOS/macOS, Windows 10/11, and Mozilla Firefox by handling platform-specific network probes.
- **Embedded Web Assets**: Serves the portal landing page directly from compiled binary memory symbols (`_binary_src_data_main_html_start`), removing filesystem read overhead during peak connection bursts.
- **Thread-Safe Storage**: Manages CSV log entries on LittleFS with FreeRTOS mutexes (`SemaphoreHandle_t`), avoiding filesystem corruption when concurrent connections attempt write/read operations.
- **Elliptic Curve Cryptography (mbedTLS)**: Implements NIST P-256 (SECP256R1) ECDH key agreement with hardware-backed pseudo-random number generation (`mbedtls_ctr_drbg`).
- **HKDF Key Derivation**: Derives high-entropy 256-bit AES symmetric keys using HKDF-Extract and HKDF-Expand (RFC 5869) with SHA-256.
- **Hardware-Accelerated AES-256-CBC**: Utilizes ESP32 on-chip cryptographic hardware acceleration via mbedTLS with PKCS#7 padding and fresh 16-byte random IVs (`esp_fill_random`) per response.
- **Automatic Purge on Read**: Re-initializes `/log.csv` immediately upon retrieval to enforce operational cleanliness and limit exposure time of captured logs.

---

## Operational Workflow

### Phase 1: Victim Connection & Captive Portal Redirection

1. The victim connects to the ESP32 SoftAP (open Wi-Fi network).
2. The device triggers OS network-check requests (`/generate_204`, `/hotspot-detect.html`, `/connecttest.txt`, etc.).
3. The DNS server (`dns_configurator`) redirects all domain inquiries to the ESP32 local gateway (`192.168.4.1`).
4. `captive_portal_controller` catches the probes and issues 302 redirects to `http://192.168.4.1/`.
5. The device displays the login page stored in flash.
6. The user submits credentials to `POST /api/add-access`.
7. `access_controller` records the timestamped credentials, client IP, content type, and `User-Agent` header into `/log.csv` through `access_repository` and returns HTTP 200 with the payload `"Never trust a free WiFi"`.

```
Victim Device                          ESP32 Access Point
     |                                          |
     |----- Probe Request (e.g. generate_204) ->|
     |<---- 302 Redirect to 192.168.4.1 --------|
     |                                          |
     |----- GET / ----------------------------->|
     |<---- 200 OK (Embedded main.html) --------|
     |                                          |
     |----- POST /api/add-access (Credentials) >|
     |      [username, password, User-Agent]    |
     |                                          |-- [Lock Mutex]
     |                                          |-- [Append /log.csv]
     |                                          |-- [Release Mutex]
     |<---- 200 OK ("Never trust a free WiFi") -|
```

### Phase 2: Administrative ECDH Handshake & Encrypted Data Retrieval

1. **Server Public Key Request**: The administrator client executes `GET /api/ecdh/public-key`. The ESP32 generates an ephemeral SECP256R1 key pair, stores the context in memory, and returns its Base64-encoded uncompressed public key.
2. **Client Key Exchange**: The administrator generates its own SECP256R1 key pair, converts its public key to Base64, and sends it via `POST /api/ecdh/client-key` (`key=<base64>`).
3. **Shared Secret & HKDF Key Derivation**: Both parties independently compute the 32-byte shared secret (`Z`). The ESP32 runs HKDF-SHA256 (`salt="salt"`, `info="Info"`) to derive a 256-bit AES session key and registers it in `crypto_cipher`.
4. **Encrypted Log Retrieval**: The administrator issues `GET /api/access`.
5. **Cipher & Wipe**: The ESP32 loads `/log.csv`, encrypts the CSV payload with AES-256-CBC (prepending a random 16-byte IV), streams the binary response (`application/octet-stream`), and flushes the log file.
6. **Decryption**: The administrator extracts the IV and decrypts the ciphertext using the derived AES session key.

```
Admin Client                            ESP32 Access Point
     |                                          |
     |----- GET /api/ecdh/public-key ---------->|
     |<---- 200 OK (Server Base64 Public Key) --|
     |                                          |
     | [Generate Client ECDH Key Pair]          |
     | [Compute Shared Secret & HKDF AES Key]   |
     |                                          |
     |----- POST /api/ecdh/client-key --------->|
     |      Body: key=<Client Base64 Public Key>|
     |                                          |-- [Compute Shared Secret]
     |                                          |-- [Derive HKDF AES Key]
     |<---- 200 OK ("Key generated") -----------|
     |                                          |
     |----- GET /api/access ------------------->|
     |                                          |-- [Read /log.csv]
     |                                          |-- [Generate 16-byte random IV]
     |                                          |-- [AES-256-CBC Encrypt]
     |                                          |-- [Clean & Reset /log.csv]
     |<---- 200 OK (Binary: IV + Ciphertext) ---|
     |                                          |
     | [Decrypt with AES Key + Extracted IV]    |
     | [Parse Plaintext CSV Logs]               |
```

---

## REST API Reference

### Captive Portal & Detection Probes

| Route | Method | Description | Response |
| :--- | :--- | :--- | :--- |
| `/` | `GET`, `POST`, `ANY` | Serves embedded captive portal page (`main.html`) | `200 text/html` |
| `/generate_204` | `GET` | Android captive portal probe | `302 -> http://192.168.4.1/` |
| `/hotspot-detect.html` | `GET` | Apple (iOS / macOS) captive portal probe | `302 -> http://192.168.4.1/` |
| `/connecttest.txt` | `GET` | Windows 11 captive portal probe workaround | `302 -> http://logout.net` |
| `/redirect` | `GET` | Microsoft connectivity redirect | `302 -> http://192.168.4.1/` |
| `/ncsi.txt` | `GET` | Windows Network Connectivity Status Indicator | `302 -> http://192.168.4.1/` |
| `/canonical.html` | `GET` | Firefox captive portal detection probe | `302 -> http://192.168.4.1/` |
| `/success.txt` | `GET` | Firefox connectivity check probe | `200 text/plain` |
| `/wpad.dat` | `GET` | Web Proxy Auto-Discovery Protocol | `404 Not Found` |
| `onNotFound` | `ANY` | Wildcard fallback for unmapped hostnames/URLs | `302 -> http://192.168.4.1/` |

### Credential Harvesting API

#### `POST /api/add-access`
Submits victim credentials captured from the captive portal interface.

- **Content-Type**: `application/x-www-form-urlencoded` or `multipart/form-data`
- **Request Parameters**:
  - `username` *(string, required)*: Captured login identifier.
  - `password` *(string, required)*: Captured password.
- **Captured Metadata**:
  - Remote IP address (`request->client()->remoteIP()`).
  - `User-Agent` HTTP header.
  - `Content-Type` HTTP header.
- **Responses**:
  - `200 text/plain`: `"Never trust a free WiFi"`
  - `400 text/plain`: `"Missing paramters"`
  - `500 text/plain`: `"Error during the access"`

### Cryptographic Handshake & Exfiltration API

#### `GET /api/ecdh/public-key`
Initiates the ECDH handshake. The server generates an ephemeral SECP256R1 key pair and outputs its public key.

- **Responses**:
  - `200 text/plain`: Base64-encoded uncompressed public key string (e.g. `BC1...`).
  - `500 text/plain`: `Error: <code>`

#### `POST /api/ecdh/client-key`
Submits the administrator's Base64-encoded SECP256R1 public key. Computes the shared secret, runs HKDF, and configures the session AES key.

- **Content-Type**: `application/x-www-form-urlencoded`
- **Request Parameters**:
  - `key` *(string, required)*: Base64-encoded client uncompressed public key.
- **Responses**:
  - `200 text/plain`: `"Key generated"`
  - `400 text/plain`: `"Missing 'key' POST parameter"`
  - `500 text/plain`: `Error: <code>`

#### `GET /api/access`
Retrieves all captured records encrypted with the active AES-256 session key. Once retrieved, `/log.csv` is wiped and reset.

- **Headers Sent**: `Content-Type: application/octet-stream`
- **Response**: Binary stream containing `[16-byte IV] + [AES-256-CBC Ciphertext]`.
- **Responses**:
  - `200 application/octet-stream`: Binary payload.
  - `500 text/plain`: `"Error during the cypher"`

---

## Data Storage & Concurrency Control

Captured credentials are stored on the LittleFS flash partition at `/log.csv`. 

### CSV Schema
```csv
username,password,ip,contentType,userAgent
```

### Mutex Synchronization
Because `ESPAsyncWebServer` runs asynchronously across FreeRTOS worker tasks, concurrent HTTP requests could invoke filesystem operations simultaneously. All LittleFS reads, writes, and truncations are guarded by:
- `SemaphoreHandle_t fsMutex`: FreeRTOS binary mutex.
- `mutexTimeout`: `pdMS_TO_TICKS(2000)` (2-second timeout window).
- `access_repository::clean()`: Atomic file removal and header re-initialization executed immediately following successful `/api/access` encryption.


## Project File Structure

```
.
├── src/
│   ├── main.cpp                              # System bootstrap, FS mount & loop
│   ├── access/
│   │   ├── controller/
│   │   │   ├── access_controller.h           # Route definitions for credentials & log access
│   │   │   └── access_controller.cpp         # Route implementations & cipher triggers
│   │   └── repository/
│   │       ├── access_repository.h           # Thread-safe file operations API
│   │       └── access_repository.cpp         # LittleFS /log.csv mutex read/write/wipe
│   ├── captive_portal/
│   │   └── controller/
│   │       ├── captive_portal_controller.h   # Captive portal route definitions
│   │       └── captive_portal_controller.cpp # OS probe handlers & 302 redirection rules
│   ├── cryptography/
│   │   ├── controller/
│   │   │   ├── cryptography_controller.h     # Handshake route definitions
│   │   │   └── cryptography_controller.cpp   # GET/POST /api/ecdh handlers
│   │   ├── service/
│   │   │   ├── crypto_cipher.h               # Symmetric cipher interface
│   │   │   ├── crypto_cipher.cpp             # AES-256-CBC encryption & PKCS#7 padding
│   │   │   ├── ecdh_exchange.h               # mbedTLS ECDH operations API
│   │   │   ├── ecdh_exchange.cpp             # SECP256R1 keypair generation & secret compute
│   │   │   ├── session_orchestrator.h        # Cryptographic session manager
│   │   │   └── session_orchestrator.cpp      # Coordinates ECDH, HKDF, and session keys
│   │   └── utils/
│   │       ├── derive_key.h                  # Key derivation function interface
│   │       └── derive_key.cpp                # RFC 5869 HKDF-SHA256 implementation
│   ├── network/
│   │   ├── ap_configurator.h                 # SoftAP SSID, IP, and subnet configuration
│   │   ├── ap_configurator.cpp
│   │   ├── dns_configurator.h                # Captive DNS redirector (port 53)
│   │   └── dns_configurator.cpp
│   └── server/
│       ├── web_server.h                      # AsyncWebServer lifecycle control
│       └── web_server.cpp                    # Port 80 binding & controller route registration
└── platformio.ini                            # PlatformIO build configuration & dependencies
```

---

## Build, Dependencies & Flashing

### Framework & Dependencies
- **Core Platform**: Espressif 32 (`espressif32`)
- **Framework**: Arduino
- **Required Libraries**:
  - `ESPAsyncWebServer` (Asynchronous HTTP server)
  - `LittleFS` (SPIFFS replacement for onboard flash storage)
  - `mbedTLS` (Built into ESP-IDF / Arduino ESP32 core)

### Example `platformio.ini`
```ini
[env:upesy_wroom]
platform = espressif32
board = upesy_wroom
framework = arduino 
lib_deps = 
	ottowinter/ESPAsyncWebServer-esphome @ ^3.1.0
	esphome/AsyncTCP-esphome @ ^2.1.1
monitor_port = /dev/cu.usbserial-130
monitor_speed = 115200
board_build.embed_txtfiles = 
    src/data/main.html
```

### Build & Deploy Instructions
1. Clone or organize the project directory.
2. Ensure `src/data/main.html` exists for the linker symbol `_binary_src_data_main_html_start`.
3. Connect your ESP32 board over USB.
4. Run build and flash:
   ```bash
   pio run --target upload
   ```
5. Monitor serial output:
   ```bash
   pio device monitor -b 115200
   ```

---

## Legal & Ethical Disclaimer

**IMPORTANT NOTICE**: This project is developed exclusively for educational purposes, academic research, authorized penetration testing, and security awareness demonstrations. 

Deploying rogue access points, intercepting network communications, or capturing authentication credentials on networks without explicit, written authorization from all participating parties is illegal and punishable under regional and international cybersecurity laws (e.g., Computer Fraud and Abuse Act in the US, Article 615-ter of the Italian Penal Code, and the European Union Cybercrime Directive). The authors and contributors assume no liability for misuse, damages, or legal repercussions resulting from the use or deployment of this software.
