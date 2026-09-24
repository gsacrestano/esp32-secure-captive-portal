#include "derive_key.h"

#include <HardwareSerial.h>

#include <cstring>

#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

namespace derive_key
{

bool derive_aes_key(const uint8_t* shared_secret, size_t secret_len, const uint8_t* salt,
                    size_t salt_len, const char* info_label, uint8_t derived_key[32])
{
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return false;

    // 1. HKDF-Extract: PRK = HMAC-SHA256(salt, secret)
    uint8_t prk[32], zero_salt[32] = {0};
    const uint8_t* s_ptr = (salt && salt_len) ? salt : zero_salt;
    size_t s_len = (salt && salt_len) ? salt_len : sizeof(zero_salt);

    if (mbedtls_md_hmac(md, s_ptr, s_len, shared_secret, secret_len, prk) != 0) return false;

    // 2. HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    size_t info_len = info_label ? strlen(info_label) : 0;
    uint8_t msg[info_len + 1];  // Stack-allocated VLA
    if (info_len) memcpy(msg, info_label, info_len);
    msg[info_len] = 0x01;

    int ret = mbedtls_md_hmac(md, prk, sizeof(prk), msg, info_len + 1, derived_key);

    mbedtls_platform_zeroize(prk, sizeof(prk));
    return (ret == 0);
}

}  // namespace derive_key