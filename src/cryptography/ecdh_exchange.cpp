#include "ecdh_exchange.h"

#include "cstring"
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

}  // namespace ecdh_exchange
