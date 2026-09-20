#include "ecdh_exchange.h"

#include <HardwareSerial.h>

#include "cstring"
#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"

namespace
{
mbedtls_ecdh_context ctx;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

}  // namespace

namespace ecdh_exchange
{
int generate_local_key(char* buf, size_t buf_len, size_t* olen)
{
    mbedtls_ecdh_init(&ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    int outcome;

    const char* pers = "ecdh_init";

    outcome = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char*)pers, strlen(pers));
    if (outcome != 0) return -1;

    outcome = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (outcome != 0) return -1;

    outcome = mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (outcome != 0) return -1;

    outcome = mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, olen,
                                             (unsigned char*)buf, buf_len);
    if (outcome != 0) return -1;

    return 0;
}

int key_to_base64(char* buf, size_t len, char* dest, size_t dest_len)
{
    size_t b64_len = 0;

    int outcome = mbedtls_base64_encode((unsigned char*)dest, dest_len, &b64_len,
                                        (const unsigned char*)buf, len);
    if (outcome != 0) return outcome;
    if (dest_len <= b64_len)
        return -1;
    else
    {
        dest[b64_len] = '\0';
        return 0;
    }
}

int base64_to_key(char* buf, size_t len, size_t* out_len, char* dest, size_t dest_len)
{
    int outcome =
        mbedtls_base64_decode((unsigned char*)dest, dest_len, out_len, (unsigned char*)buf, len);
    return outcome;
}

int compute_secret(unsigned char* buf, size_t buf_len)
{
    int outcome = mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Qp, buf, buf_len);
    if (outcome != 0) return outcome;

    outcome = mbedtls_ecdh_compute_shared(&ctx.grp, &ctx.z, &ctx.Qp, &ctx.d, NULL, NULL);
    if (outcome != 0) return outcome;
    return outcome;
}
}  // namespace ecdh_exchange
