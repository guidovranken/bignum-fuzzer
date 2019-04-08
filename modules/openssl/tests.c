#include <openssl/bn.h>
#ifndef BIGNUM_FUZZER_BORINGSSL
#include <openssl/srp.h>
#endif
#include <openssl/rsa.h>
#include <stdlib.h>
#include "tests.h"
#include "sanity.h"

extern BN_CTX *ctx;
extern BIGNUM *zero;

void test_bn_sqrx8x_internal(const BIGNUM *B, const BIGNUM *C)
{
    /* Test for bn_sqrx8x_internal carry bug on x86_64 (CVE-2017-3736) */
    if ( BN_cmp(C, B) >= 0 &&
            BN_cmp(B, zero) > 0 ) /* this automatically implies that C is also positive */ {
        BN_MONT_CTX* mont = BN_MONT_CTX_new();
        BIGNUM* Bcopy = BN_dup(B);
        if ( BN_MONT_CTX_set(mont, C, ctx) != 0 ) {
            BIGNUM* x = BN_new();
            test_bn_mont_ctx_sanity(mont);
            if ( BN_mod_mul_montgomery(x, B, B, mont, ctx) != 0 ) {
                BIGNUM* y = BN_new();
                test_bn_mont_ctx_sanity(mont);
                if ( BN_mod_mul_montgomery(y, B, Bcopy, mont, ctx) != 0 ) {
                    test_bn_mont_ctx_sanity(mont);
                    if ( BN_cmp(x, y) != 0 ) {
                        abort();
                    }
                }
                BN_free(y);
            }
            BN_free(x);
        }
        BN_MONT_CTX_free(mont);
        BN_free(Bcopy);
    }
}

void test_rsaz_1024_mul_avx2(const BIGNUM* A, const BIGNUM *B, const BIGNUM *C)
{
    /* Test for rsaz_1024_mul_avx2 overflow bug on x86_64 (CVE-2017-3738) */
    if ( BN_cmp(C, zero) > 0 &&
            BN_cmp(B, zero) > 0 &&
            BN_cmp(A, zero) > 0 ) {
        BN_MONT_CTX* mont = BN_MONT_CTX_new();
        if ( BN_MONT_CTX_set(mont, C, ctx) != 0 ) {
            BIGNUM* x = BN_new();
            test_bn_mont_ctx_sanity(mont);
            if ( BN_mod_exp_mont_consttime(x, A, B, C, ctx, mont) != 0 ) {
                BIGNUM* y = BN_new();
                test_bn_mont_ctx_sanity(mont);
                if ( BN_mod_exp_mont(y, A, B, C, ctx, mont) != 0 ) {
                    test_bn_mont_ctx_sanity(mont);
                    if ( BN_cmp(x, y) != 0 ) {
                        abort();
                    }
                }
                BN_free(y);
            }
            BN_free(x);
        }
        BN_MONT_CTX_free(mont);
    }
}

void test_BN_mod_sqrt(const BIGNUM *B, const BIGNUM *C)
{
    BIGNUM* tmp1 = BN_new();
    BIGNUM* tmp2 = BN_new();

    if ( BN_cmp(B, zero) < 0 || BN_cmp(C, zero) < 0 ) {
        goto end;
    }

    if ( BN_num_bits(B) > 512 || BN_num_bits(C) > 512 ) {
        goto end;
    }

    /* C must be prime */
    if ( BN_is_prime_ex(C, 0, NULL, NULL) != 1 ) {
        goto end;
    }

    if ( BN_mod_sqrt(tmp1, B, C, ctx) == NULL ) {
        goto end;
    }

    if ( BN_sqr(tmp1, tmp1, ctx) != 1 ) {
        goto end;
    }

    if ( BN_mod(tmp1, tmp1, C, ctx) != 1 ) {
        goto end;
    }

    if ( BN_copy(tmp2, B) == NULL ) {
        goto end;
    }

    if ( BN_mod(tmp2, tmp2, C, ctx) != 1 ) {
        goto end;
    }

    /* tmp1 and tmp2 must be the same */

    if ( BN_cmp(tmp1, tmp2) != 0 ) {
        abort();
    }

end:
	BN_free(tmp1);
	BN_free(tmp2);
}

void test_SRP(const BIGNUM *A, const BIGNUM *B)
{
#if !defined(BIGNUM_FUZZER_BORINGSSL) && !defined(BIGNUM_FUZZER_LIBRESSL)
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;

    BIGNUM *s = NULL;
    BIGNUM *v = NULL;

    BIGNUM *Apub = NULL;
    BIGNUM *Bpub = NULL;

    BIGNUM *Kclient = NULL;
    BIGNUM *Kserver = NULL;

    BIGNUM *u = NULL;
    BIGNUM *x = NULL;

    const SRP_gN *GN = NULL;

    int i;

    if ( BN_cmp(A, zero) < 0 || BN_cmp(B, zero) < 0 ) {
        return;
    }

    a = BN_dup(A);
    b = BN_dup(A);

    if ( a == NULL || b == NULL ) {
        goto end;
    }

    GN = SRP_get_default_gN("1024");
    if (GN == NULL) {
        goto end;
    }

    if (!SRP_create_verifier_BN("alice", "password", &s, &v, GN->N, GN->g)) {
        goto end;
    }

    Bpub = SRP_Calc_B(b, GN->N, GN->g, v);
    if (!SRP_Verify_B_mod_N(Bpub, GN->N)) {
        goto end;
    }

    Apub = SRP_Calc_A(a, GN->N, GN->g);
    if (!SRP_Verify_A_mod_N(Apub, GN->N)) {
        goto end;
    }

    u = SRP_Calc_u(Apub, Bpub, GN->N);
    x = SRP_Calc_x(s, "alice", "password");
    Kclient = SRP_Calc_client_key(GN->N, Bpub, GN->g, x, a, u);
    Kserver = SRP_Calc_server_key(Apub, v, u, b, GN->N);

    if (BN_cmp(Kclient, Kserver) != 0) {
        abort();
    }

end:
    BN_free(Kclient);
    BN_free(Kserver);
    BN_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_free(Bpub);
    BN_free(s);
    BN_free(v);
    BN_free(a);
    BN_free(b);
#endif
}

void test_BN_mod_inverse(const BIGNUM *B, const BIGNUM *C)
{
    BIGNUM* inv = BN_new();
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    /* TODO evaluate whether negative numbers are OK,
     * and remove the following restriction if so. */
    if ( BN_cmp(B, zero) < 0 || BN_cmp(C, zero) == 0 ) {
        goto end;
    }
    if ( BN_mod_inverse(inv, B, C, ctx) == NULL ) {
        goto end;
    }
    if ( BN_mul(inv, inv, B, ctx) != 1 ) {
        goto end;
    }
    if ( BN_mod(inv, inv, C, ctx) != 1 ) {
        goto end;
    }
    if ( BN_cmp(C, one) != 0) {
        if ( BN_cmp(inv, one) != 0 ) {
            abort();
        }
    }
end:
    BN_free(inv);
    BN_free(one);
}

void test_RSA_public_encrypt(const BIGNUM *B, const BIGNUM *C, const BIGNUM *D)
{
    RSA* rsa = NULL;
    BIGNUM *n = NULL, *e = NULL;
    unsigned char *plaintext = NULL, *ciphertext = NULL;
    int plaintext_len = 0, ciphertext_len = 0, encrypted_len = 0;

    rsa = RSA_new();

    ciphertext_len = BN_num_bytes(B);
    ciphertext = malloc(ciphertext_len);

    plaintext = malloc(BN_num_bytes(D));
    plaintext_len = BN_bn2bin(D, plaintext);

    n = BN_new();
    e = BN_new();
    BN_copy(n, B);
    BN_copy(e, C);
    RSA_set0_key(rsa, n, e, NULL);

    encrypted_len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, RSA_PKCS1_PADDING);
    if ( encrypted_len > ciphertext_len ) {
        /* This implies a buffer overflow of 'ciphertext'.
         * Abort in case AddressSanitizer is not enabled.
         */
        abort();
    }

    free(plaintext);
    free(ciphertext);
    RSA_free(rsa);
}
