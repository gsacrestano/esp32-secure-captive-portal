import os
import base64
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ESP_IP = os.getenv("ESP_IP", "192.168.4.1")
BASE_URL = f"http://{ESP_IP}"

print(f"[*] Targeting ESP32 at: {BASE_URL}")

# 1. Fetch ESP32 ephemeral public key
res_esp_key = requests.get(f"{BASE_URL}/api/ecdh/public-key", timeout=5)
if res_esp_key.status_code != 200:
    raise RuntimeError(f"Failed to fetch ESP32 public key: {res_esp_key.status_code} - {res_esp_key.text}")

esp_pub_b64 = res_esp_key.text.strip()
esp_pub_raw = base64.b64decode(esp_pub_b64)

# Load ESP32 peer public key (SECP256R1 uncompressed point format)
esp_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), esp_pub_raw)

# 2. Generate Client keypair (P-256)
client_private_key = ec.generate_private_key(ec.SECP256R1())
client_pn = client_private_key.public_key().public_numbers()

# Compose 65-byte uncompressed point: 0x04 || X (32B) || Y (32B)
raw_point = b"\x04" + client_pn.x.to_bytes(32, "big") + client_pn.y.to_bytes(32, "big")
payload_b64 = base64.b64encode(raw_point).decode("utf-8")

# 3. Compute raw ECDH shared secret
shared_secret = client_private_key.exchange(ec.ECDH(), esp_pub_key)

# 4. Derive AES-256 session key matching the ESP32 parameters
derived_aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"salt",
    info=b"Info"
).derive(shared_secret)

print(f"[*] Client Public Key generated and prepared.")

# 5. Send Client public key to ESP32 to establish session
post_url = f"{BASE_URL}/api/ecdh/client-key"
res_handshake = requests.post(post_url, data={"key": payload_b64}, timeout=5)

if res_handshake.status_code != 200:
    print(f"[!] Handshake failed: {res_handshake.status_code} - {res_handshake.text}")
    exit(1)

print(f"[*] Handshake response: {res_handshake.text.strip()}")

# 6. Fetch encrypted data from /api/access
data_url = f"{BASE_URL}/api/access"
res_data = requests.get(data_url, timeout=5)

if res_data.status_code != 200:
    print(f"[!] Failed to fetch data: {res_data.status_code} - {res_data.text}")
    exit(1)

payload = res_data.content
if len(payload) < 32:
    raise ValueError(f"Payload too short ({len(payload)} bytes), expected at least 32 bytes")

# 7. Extract IV (first 16 bytes) and Ciphertext (remaining bytes)
iv = payload[:16]
ciphertext = payload[16:]

print(f"[*] Payload received: {len(payload)} bytes (IV: {len(iv)}b, Ciphertext: {len(ciphertext)}b)")

# 8. Decrypt with AES-256-CBC and remove PKCS#7 padding
cipher = Cipher(algorithms.AES(derived_aes_key), modes.CBC(iv))
decryptor = cipher.decryptor()
padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()
plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

print("\n--- DECRYPTED LOGS ---")
print(plaintext.decode('utf-8'))
print("----------------------")