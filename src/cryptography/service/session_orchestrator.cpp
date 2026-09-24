#include "session_orchestrator.h"

#include <stddef.h>

#include <cstring>

#include "../utils/derive_key.h"
#include "crypto_cipher.h"
#include "ecdh_exchange.h"

namespace session_orchestrator
{
int generate_public_key(char* response_string, size_t response_string_size)
{
    char pub_key_buf[65];
    size_t len = 0;

    int outcome = ecdh_exchange::generate_local_key(pub_key_buf, sizeof(pub_key_buf), &len);
    if (outcome != 0) return outcome;

    outcome = ecdh_exchange::key_to_base64(pub_key_buf, len, response_string, response_string_size);
    if (outcome != 0) return outcome;

    return 0;
}

int generate_aes_key(char* b64, size_t b64_size)
{
    unsigned char client_key_buf[65];
    size_t out_len = 0;

    int outcome = ecdh_exchange::base64_to_key(b64, b64_size, &out_len, (char*)client_key_buf,
                                               sizeof(client_key_buf));
    if (outcome != 0) return outcome;

    uint8_t shared_secret[32];
    outcome = ecdh_exchange::compute_secret(client_key_buf, out_len, shared_secret);
    if (outcome != 0) return outcome;

    const char* salt = "salt";
    uint8_t derived_key[32];
    if (!derive_key::derive_aes_key(shared_secret, 32, (const uint8_t*)salt, 4, "Info",
                                    derived_key))
        return -1;

    crypto_cipher::set_session_key(derived_key);
    return 0;
}
int encrypt_payload(uint8_t* output, size_t output_size, size_t* o_len)
{
    const char* input = "Hello World";
    if (!crypto_cipher::encrypt_data((const uint8_t*)input, strlen(input), output, output_size,
                                     o_len))
        return -1;

    return 0;
}
}  // namespace session_orchestrator
