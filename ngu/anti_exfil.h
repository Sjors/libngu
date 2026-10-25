/* Experimental BIP-EXFIL single-signer Schnorr protocol. */
#ifndef NGU_ANTI_EXFIL_H
#define NGU_ANTI_EXFIL_H

#include <string.h>
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_extrakeys.h"
#include "secp256k1/include/secp256k1_schnorrsig.h"

static void ngu_ae_clear(void *data, size_t len)
{
    volatile unsigned char *p = data;
    while (len--) *p++ = 0;
}

/* A SHA256 digest is less than 2*n, so exactly one subtraction suffices.
 * Select the result without branching on the secret nonce candidate. */
static void ngu_ae_reduce(unsigned char scalar[32])
{
    static const unsigned char order[32] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,
        0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
    };
    unsigned char reduced[32];
    unsigned int borrow = 0, mask;
    int i;
    for (i = 31; i >= 0; --i) {
        unsigned int diff = (unsigned int)scalar[i] - order[i] - borrow;
        reduced[i] = diff & 255;
        borrow = (diff >> 8) & 1;
    }
    mask = 0u - (1u - borrow);
    for (i = 0; i < 32; ++i) {
        scalar[i] = (reduced[i] & mask) | (scalar[i] & ~mask);
    }
    ngu_ae_clear(reduced, sizeof(reduced));
}

static int ngu_ae_nonce(unsigned char nonce32[32], const unsigned char *msg,
                        size_t msglen, const unsigned char key32[32],
                        const unsigned char pk32[32], const unsigned char h[32])
{
    static const unsigned char tag[] = "BIP-EXFIL/nonce";
    int ok = secp256k1_nonce_function_bip340(nonce32, msg, msglen, key32,
                                          pk32, tag, sizeof(tag)-1, (void *)h);
    ngu_ae_reduce(nonce32);
    return ok;
}

static int ngu_anti_exfil_commit(const secp256k1_context *ctx,
                                unsigned char nonce33[33],
                                const unsigned char msg32[32],
                                const secp256k1_keypair *keypair,
                                const unsigned char h[32])
{
    unsigned char key32[32], pk32[32], nonce32[32];
    secp256k1_xonly_pubkey pk;
    secp256k1_pubkey nonce;
    size_t len = 33;
    int parity = 0, ok;
    ok = secp256k1_keypair_sec(ctx, key32, keypair);
    ok &= secp256k1_keypair_xonly_pub(ctx, &pk, &parity, keypair);
    ok &= secp256k1_xonly_pubkey_serialize(ctx, pk32, &pk);
    if (parity) ok &= secp256k1_ec_seckey_negate(ctx, key32);
    ok &= ngu_ae_nonce(nonce32, msg32, 32, key32, pk32, h);
    if (ok) ok = secp256k1_ec_pubkey_create(ctx, &nonce, nonce32);
    if (ok) ok = secp256k1_ec_pubkey_serialize(ctx, nonce33, &len, &nonce, SECP256K1_EC_COMPRESSED);
    if (!ok) memset(nonce33, 0, 33);
    ngu_ae_clear(key32, sizeof(key32));
    ngu_ae_clear(nonce32, sizeof(nonce32));
    return ok;
}

typedef struct {
    const secp256k1_context *ctx;
    const unsigned char *h;
    const unsigned char *rho;
} ngu_ae_nonce_data;

static int ngu_ae_tweaked_nonce(unsigned char *nonce32, const unsigned char *msg,
                               size_t msglen, const unsigned char *key32,
                               const unsigned char *pk32,
                               const unsigned char *algo, size_t algolen,
                               void *data)
{
    ngu_ae_nonce_data *args = data;
    int ok;
    (void)algo;
    (void)algolen;
    ok = ngu_ae_nonce(nonce32, msg, msglen, key32, pk32, args->h);
    /* This also rejects the zero original nonce and the infinite final nonce. */
    ok &= secp256k1_ec_seckey_tweak_add(args->ctx, nonce32, args->rho);
    return ok;
}

static int ngu_anti_exfil_sign(const secp256k1_context *ctx,
                              unsigned char sig64[64],
                              const unsigned char msg32[32],
                              const secp256k1_keypair *keypair,
                              const unsigned char h[32],
                              const unsigned char nonce33[33],
                              const unsigned char rho[32])
{
    static const unsigned char tag[] = "BIP-EXFIL/host";
    unsigned char computed_h[32], computed_nonce[33];
    secp256k1_xonly_pubkey pk;
    secp256k1_schnorrsig_extraparams extra = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    ngu_ae_nonce_data data = {ctx, h, rho};
    int ok;
    memset(sig64, 0, 64);
    if (!secp256k1_ec_seckey_verify(ctx, rho)) return 0;
    ok = secp256k1_tagged_sha256(ctx, computed_h, tag, sizeof(tag)-1, rho, 32);
    if (!ok || memcmp(h, computed_h, 32)) return 0;
    if (!ngu_anti_exfil_commit(ctx, computed_nonce, msg32, keypair, h)) return 0;
    if (memcmp(nonce33, computed_nonce, 33)) return 0;
    extra.noncefp = ngu_ae_tweaked_nonce;
    extra.ndata = &data;
    ok = secp256k1_schnorrsig_sign_custom(ctx, sig64, msg32, 32, keypair, &extra);
    ok &= secp256k1_keypair_xonly_pub(ctx, &pk, NULL, keypair);
    /* Fault detection is mandatory before releasing the signature. */
    ok &= secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, &pk);
    if (!ok) memset(sig64, 0, 64);
    return ok;
}

#endif
