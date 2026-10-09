#include "authentication_service.h"

#include <cstring>

#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"

namespace authentication_service
{

const uint8_t PWD_SHA[32] = {0x03, 0xac, 0x67, 0x42, 0x16, 0xf3, 0xe1, 0x5c, 0x76, 0x1e, 0xe1,
                             0xa5, 0xe2, 0x55, 0xf0, 0x67, 0x95, 0x36, 0x23, 0xc8, 0xb3, 0x88,
                             0xb4, 0x45, 0x9e, 0x13, 0xf9, 0x78, 0xd7, 0xc8, 0x46, 0xf4};

bool is_authorized(const unsigned char* pwd, size_t pwd_len)
{
    if (pwd == nullptr || pwd_len == 0) return false;

    uint8_t output[32];
    mbedtls_sha256(pwd, pwd_len, output, 0);
    return (memcmp(output, PWD_SHA, 32) == 0);
}

}  // namespace authentication_service