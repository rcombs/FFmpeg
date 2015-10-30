/*
 * Copyright (c) 2013 Nicolas George
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with FFmpeg; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* Optional external libraries; can be enabled using:
 * make VERSUS=crypto+gcrypt+tomcrypt tools/crypto_bench */
#define USE_crypto           0x01    /* OpenSSL's libcrypto */
#define USE_gcrypt           0x02    /* GnuTLS's libgcrypt */
#define USE_tomcrypt         0x04    /* LibTomCrypt */

#include <stdlib.h>
#include <math.h>

#include "libavutil/avutil.h"
#include "libavutil/avstring.h"
#include "libavutil/crc.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/timer.h"

#ifndef AV_READ_TIME
#define AV_READ_TIME(x) 0
#endif

#if HAVE_UNISTD_H
#include <unistd.h> /* for getopt */
#endif
#if !HAVE_GETOPT
#include "compat/getopt.c"
#endif

#define MAX_INPUT_SIZE 1048576
#define MAX_OUTPUT_SIZE 128

static const char *enabled_libs;
static const char *enabled_algos;
static unsigned specified_runs;

static const uint8_t *hardcoded_key = "FFmpeg is the best program ever.";
static const uint8_t hardcoded_iv[16] = {0};

static void fatal_error(const char *tag)
{
    av_log(NULL, AV_LOG_ERROR, "Fatal error: %s\n", tag);
    exit(1);
}

struct hash_impl {
    const char *lib;
    const char *name;
    void (*run)(uint8_t *output, const uint8_t *input, unsigned size);
    const char *output;
};

/***************************************************************************
 * lavu: libavutil
 ***************************************************************************/

#include "libavutil/md5.h"
#include "libavutil/sha.h"
#include "libavutil/sha512.h"
#include "libavutil/ripemd.h"
#include "libavutil/aes.h"
#include "libavutil/blowfish.h"
#include "libavutil/camellia.h"
#include "libavutil/cast5.h"
#include "libavutil/twofish.h"
#include "libavutil/rc4.h"
#include "libavutil/xtea.h"

#define IMPL_USE_lavu IMPL_USE

static void run_lavu_md5(uint8_t *output,
                         const uint8_t *input, unsigned size)
{
    av_md5_sum(output, input, size);
}

#define DEFINE_LAVU_MD(suffix, type, namespace, hsize)                       \
static void run_lavu_ ## suffix(uint8_t *output,                             \
                                const uint8_t *input, unsigned size)         \
{                                                                            \
    static struct type *h;                                                   \
    if (!h && !(h = av_ ## namespace ## _alloc()))                           \
        fatal_error("out of memory");                                        \
    av_ ## namespace ## _init(h, hsize);                                     \
    av_ ## namespace ## _update(h, input, size);                             \
    av_ ## namespace ## _final(h, output);                                   \
}

DEFINE_LAVU_MD(sha1,      AVSHA,    sha, 160);
DEFINE_LAVU_MD(sha256,    AVSHA,    sha, 256);
DEFINE_LAVU_MD(sha512,    AVSHA512, sha512, 512);
DEFINE_LAVU_MD(ripemd128, AVRIPEMD, ripemd, 128);
DEFINE_LAVU_MD(ripemd160, AVRIPEMD, ripemd, 160);

#define DEFINE_LAVU_CRYPT(suffix, type, namespace, ivsize, sshift, ...)      \
static void run_lavu_ ## suffix(uint8_t *output,                             \
                                const uint8_t *input, unsigned size)         \
{                                                                            \
    static struct type *h;                                                   \
    static uint8_t *iv = NULL;                                               \
    if (!h && !(h = av_ ## namespace ## _alloc()))                           \
        fatal_error("out of memory");                                        \
    if (ivsize && !iv && !(iv = av_malloc(ivsize)))                          \
        fatal_error("out of memory");                                        \
    if (ivsize)                                                              \
        memcpy(iv, hardcoded_iv, ivsize);                                    \
    av_ ## namespace ## _init(h, hardcoded_key, __VA_ARGS__);                \
    av_ ## namespace ## _crypt(h, output, input, size >> sshift, iv, 0);     \
}

DEFINE_LAVU_CRYPT(aes128,    AVAES,      aes,      0,  4, 128, 0);
DEFINE_LAVU_CRYPT(aes192,    AVAES,      aes,      0,  4, 192, 0);
DEFINE_LAVU_CRYPT(aes256,    AVAES,      aes,      0,  4, 256, 0);
DEFINE_LAVU_CRYPT(aes128cbc, AVAES,      aes,      16, 4, 128, 0);
DEFINE_LAVU_CRYPT(aes192cbc, AVAES,      aes,      16, 4, 192, 0);
DEFINE_LAVU_CRYPT(aes256cbc, AVAES,      aes,      16, 4, 256, 0);
DEFINE_LAVU_CRYPT(blowfish,  AVBlowfish, blowfish, 0,  3, 16);
DEFINE_LAVU_CRYPT(camellia,  AVCAMELLIA, camellia, 0,  4, 128);
DEFINE_LAVU_CRYPT(twofish,   AVTWOFISH,  twofish,  0,  4, 128);
DEFINE_LAVU_CRYPT(rc4,       AVRC4,      rc4,      0,  0, 128, 0);

static void run_lavu_cast128(uint8_t *output,
                             const uint8_t *input, unsigned size)
{
    static struct AVCAST5 *cast;
    if (!cast && !(cast = av_cast5_alloc()))
        fatal_error("out of memory");
    av_cast5_init(cast, hardcoded_key, 128);
    av_cast5_crypt(cast, output, input, size >> 3, 0);
}

static void run_lavu_xtea(uint8_t *output,
                              const uint8_t *input, unsigned size)
{
    static struct AVXTEA *xtea;
    if (!xtea && !(xtea = av_xtea_alloc()))
        fatal_error("out of memory");
    av_xtea_init(xtea, hardcoded_key);
    av_xtea_crypt(xtea, output, input, size >> 3, NULL, 0);
}


/***************************************************************************
 * crypto: OpenSSL's libcrypto
 ***************************************************************************/

#if (USE_EXT_LIBS) & USE_crypto

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/camellia.h>
#include <openssl/cast.h>
#include <openssl/rc4.h>
#include <openssl/evp.h>

#define DEFINE_CRYPTO_WRAPPER(suffix, function)                              \
static void run_crypto_ ## suffix(uint8_t *output,                           \
                                  const uint8_t *input, unsigned size)       \
{                                                                            \
    function(input, size, output);                                           \
}

DEFINE_CRYPTO_WRAPPER(md5,       MD5)
DEFINE_CRYPTO_WRAPPER(sha1,      SHA1)
DEFINE_CRYPTO_WRAPPER(sha256,    SHA256)
DEFINE_CRYPTO_WRAPPER(sha512,    SHA512)
DEFINE_CRYPTO_WRAPPER(ripemd160, RIPEMD160)

#define DEFINE_CRYPTO_CRYPT(suffix, cipher)                                  \
static void run_crypto_ ## suffix(uint8_t *output,                           \
                                  const uint8_t *input, unsigned size)       \
{                                                                            \
    static EVP_CIPHER_CTX *ctx = NULL;                                       \
    int len = 0;                                                             \
    if (!ctx && !(ctx = EVP_CIPHER_CTX_new()))                               \
        fatal_error("out of memory");                                        \
    EVP_EncryptInit(ctx, cipher(), hardcoded_key, hardcoded_iv);             \
    EVP_EncryptUpdate(ctx, output, &len, input, size);                       \
    EVP_CIPHER_CTX_cleanup(ctx);                                             \
}

DEFINE_CRYPTO_CRYPT(aes128,    EVP_aes_128_ecb);
DEFINE_CRYPTO_CRYPT(aes192,    EVP_aes_192_ecb);
DEFINE_CRYPTO_CRYPT(aes256,    EVP_aes_256_ecb);
DEFINE_CRYPTO_CRYPT(aes128cbc, EVP_aes_128_cbc);
DEFINE_CRYPTO_CRYPT(aes192cbc, EVP_aes_192_cbc);
DEFINE_CRYPTO_CRYPT(aes256cbc, EVP_aes_256_cbc);
DEFINE_CRYPTO_CRYPT(blowfish,  EVP_bf_ecb);
DEFINE_CRYPTO_CRYPT(camellia,  EVP_camellia_128_ecb);
DEFINE_CRYPTO_CRYPT(cast128,   EVP_cast5_ecb);
DEFINE_CRYPTO_CRYPT(rc4,       EVP_rc4);

#define IMPL_USE_crypto(...) IMPL_USE(__VA_ARGS__)
#else
#define IMPL_USE_crypto(...) /* ignore */
#endif

/***************************************************************************
 * gcrypt: GnuTLS's libgcrypt
 ***************************************************************************/

#if (USE_EXT_LIBS) & USE_gcrypt

#include <gcrypt.h>

#define DEFINE_GCRYPT_WRAPPER(suffix, algo)                                  \
static void run_gcrypt_ ## suffix(uint8_t *output,                           \
                                  const uint8_t *input, unsigned size)       \
{                                                                            \
    gcry_md_hash_buffer(GCRY_MD_ ## algo, output, input, size);              \
}

DEFINE_GCRYPT_WRAPPER(md5,       MD5)
DEFINE_GCRYPT_WRAPPER(sha1,      SHA1)
DEFINE_GCRYPT_WRAPPER(sha256,    SHA256)
DEFINE_GCRYPT_WRAPPER(sha512,    SHA512)
DEFINE_GCRYPT_WRAPPER(ripemd160, RMD160)

#define DEFINE_GCRYPT_CRYPT(suffix, cipher, mode, ksize)                     \
static void run_gcrypt_ ## suffix(uint8_t *output,                           \
                                  const uint8_t *input, unsigned size)       \
{                                                                            \
    static gcry_cipher_hd_t ctx = NULL;                                      \
    if (!ctx)                                                                \
        gcry_cipher_open(&ctx, cipher, mode, 0);                             \
    if (!ctx)                                                                \
        fatal_error("out of memory");                                        \
    if (mode == GCRY_CIPHER_MODE_CBC)                                        \
        gcry_cipher_setiv(ctx, hardcoded_iv, 16);                            \
    gcry_cipher_setkey(ctx, hardcoded_key, ksize);                           \
    gcry_cipher_encrypt(ctx, output, size, input, size);                     \
}

DEFINE_GCRYPT_CRYPT(aes128,    GCRY_CIPHER_AES128,      GCRY_CIPHER_MODE_ECB, 16);
DEFINE_GCRYPT_CRYPT(aes192,    GCRY_CIPHER_AES192,      GCRY_CIPHER_MODE_ECB, 24);
DEFINE_GCRYPT_CRYPT(aes256,    GCRY_CIPHER_AES256,      GCRY_CIPHER_MODE_ECB, 32);
DEFINE_GCRYPT_CRYPT(aes128cbc, GCRY_CIPHER_AES128,      GCRY_CIPHER_MODE_CBC, 16);
DEFINE_GCRYPT_CRYPT(aes192cbc, GCRY_CIPHER_AES192,      GCRY_CIPHER_MODE_CBC, 24);
DEFINE_GCRYPT_CRYPT(aes256cbc, GCRY_CIPHER_AES256,      GCRY_CIPHER_MODE_CBC, 32);
DEFINE_GCRYPT_CRYPT(blowfish,  GCRY_CIPHER_BLOWFISH,    GCRY_CIPHER_MODE_ECB, 16);
DEFINE_GCRYPT_CRYPT(camellia,  GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_ECB, 16);
DEFINE_GCRYPT_CRYPT(cast128,   GCRY_CIPHER_CAST5,       GCRY_CIPHER_MODE_ECB, 16);
DEFINE_GCRYPT_CRYPT(twofish,   GCRY_CIPHER_TWOFISH128,  GCRY_CIPHER_MODE_ECB, 16);

#define IMPL_USE_gcrypt(...) IMPL_USE(__VA_ARGS__)
#else
#define IMPL_USE_gcrypt(...) /* ignore */
#endif

/***************************************************************************
 * tomcrypt: LibTomCrypt
 ***************************************************************************/

#if (USE_EXT_LIBS) & USE_tomcrypt

#include <tomcrypt.h>

#define DEFINE_TOMCRYPT_WRAPPER(suffix, namespace, algo)                     \
static void run_tomcrypt_ ## suffix(uint8_t *output,                         \
                                    const uint8_t *input, unsigned size)     \
{                                                                            \
    hash_state md;                                                           \
    namespace ## _init(&md);                                                 \
    namespace ## _process(&md, input, size);                                 \
    namespace ## _done(&md, output);                                         \
}

DEFINE_TOMCRYPT_WRAPPER(md5,       md5,    MD5)
DEFINE_TOMCRYPT_WRAPPER(sha1,      sha1,   SHA1)
DEFINE_TOMCRYPT_WRAPPER(sha256,    sha256, SHA256)
DEFINE_TOMCRYPT_WRAPPER(sha512,    sha512, SHA512)
DEFINE_TOMCRYPT_WRAPPER(ripemd128, rmd128, RIPEMD128)
DEFINE_TOMCRYPT_WRAPPER(ripemd160, rmd160, RIPEMD160)

#define DEFINE_TOMCRYPT_CRYPT(suffix, cipher, mode, modetype, ksize, ...)    \
static void run_tomcrypt_ ## suffix(uint8_t *output,                         \
                                    const uint8_t *input, unsigned size)     \
{                                                                            \
    symmetric_ ## modetype ctx;                                              \
    int c = find_cipher(#cipher);                                            \
    if (c == -1)                                                             \
        fatal_error("cipher '" #cipher "' not found");                       \
    mode ## _start(c, __VA_ARGS__, ksize, 0, &ctx);                          \
    mode ## _encrypt(input, output, size, &ctx);                             \
}

DEFINE_TOMCRYPT_CRYPT(aes128,    aes,      ecb, ECB, 16, hardcoded_key);
DEFINE_TOMCRYPT_CRYPT(aes192,    aes,      ecb, ECB, 24, hardcoded_key);
DEFINE_TOMCRYPT_CRYPT(aes256,    aes,      ecb, ECB, 32, hardcoded_key);
DEFINE_TOMCRYPT_CRYPT(aes128cbc, aes,      cbc, CBC, 16, hardcoded_iv, hardcoded_key);
DEFINE_TOMCRYPT_CRYPT(aes192cbc, aes,      cbc, CBC, 24, hardcoded_iv, hardcoded_key);
DEFINE_TOMCRYPT_CRYPT(aes256cbc, aes,      cbc, CBC, 32, hardcoded_iv, hardcoded_key);

#define DEFINE_TOMCRYPT_CRYPT2(suffix, cipher, ksize, bsize)                 \
static void run_tomcrypt_ ## suffix(uint8_t *output,                         \
                                    const uint8_t *input, unsigned size)     \
{                                                                            \
    symmetric_key ctx;                                                       \
    unsigned i;                                                              \
    cipher ## _setup(hardcoded_key, ksize, 0, &ctx);                         \
    for (i = 0; i < size; i += bsize)                                        \
        cipher ## _ecb_encrypt(input + i, output + i, &ctx);                 \
}

DEFINE_TOMCRYPT_CRYPT2(blowfish, blowfish, 16, 8);
DEFINE_TOMCRYPT_CRYPT2(camellia, camellia, 16, 16);
DEFINE_TOMCRYPT_CRYPT2(cast128,  cast5,    16, 8);
DEFINE_TOMCRYPT_CRYPT2(twofish,  twofish,  16, 16);
DEFINE_TOMCRYPT_CRYPT2(xtea,     xtea,     16, 8);


#define IMPL_USE_tomcrypt(...) IMPL_USE(__VA_ARGS__)
#else
#define IMPL_USE_tomcrypt(...) /* ignore */
#endif

/***************************************************************************
 * Driver code
 ***************************************************************************/

static unsigned crc32(const uint8_t *data, unsigned size)
{
    return av_crc(av_crc_get_table(AV_CRC_32_IEEE), 0, data, size);
}

static void run_implementation(const uint8_t *input, uint8_t *output,
                               struct hash_impl *impl, unsigned size)
{
    uint64_t t0, t1;
    unsigned nruns = specified_runs ? specified_runs : (1 << 30) / size;
    unsigned outlen = 0, outcrc = 0;
    unsigned i, j, val;
    double mtime, ttime = 0, ttime2 = 0, stime;
    uint8_t outref[MAX_OUTPUT_SIZE];

    if (enabled_libs  && !av_stristr(enabled_libs,  impl->lib) ||
        enabled_algos && !av_stristr(enabled_algos, impl->name))
        return;
    if (!sscanf(impl->output, "crc:%x", &outcrc)) {
        outlen = strlen(impl->output) / 2;
        for (i = 0; i < outlen; i++) {
            sscanf(impl->output + i * 2, "%02x", &val);
            outref[i] = val;
        }
    }
    for (i = 0; i < 8; i++) /* heat caches */
        impl->run(output, input, size);
    for (i = 0; i < nruns; i++) {
        memset(output, 0, size); /* avoid leftovers from previous runs */
        t0 = AV_READ_TIME();
        impl->run(output, input, size);
        t1 = AV_READ_TIME();
        if (outlen ? memcmp(output, outref, outlen) :
                     crc32(output, size) != outcrc) {
            fprintf(stderr, "Expected: ");
            if (outlen)
                for (j = 0; j < outlen; j++)
                    fprintf(stderr, "%02x", output[j]);
            else
                fprintf(stderr, "%08x", crc32(output, size));
            fprintf(stderr, "\n");
            fatal_error("output mismatch");
        }
        mtime = (double)(t1 - t0) / size;
        ttime  += mtime;
        ttime2 += mtime * mtime;
    }

    ttime  /= nruns;
    ttime2 /= nruns;
    stime = sqrt(ttime2 - ttime * ttime);
    printf("%-10s %-12s size: %7d  runs: %6d  time: %8.3f +- %.3f\n",
           impl->lib, impl->name, size, nruns, ttime, stime);
    fflush(stdout);
}

#define IMPL_USE(lib, name, symbol, output) \
    { #lib, name, run_ ## lib ## _ ## symbol, output },
#define IMPL(lib, ...) IMPL_USE_ ## lib(lib, __VA_ARGS__)
#define IMPL_ALL(...) \
    IMPL(lavu,       __VA_ARGS__) \
    IMPL(crypto,     __VA_ARGS__) \
    IMPL(gcrypt,     __VA_ARGS__) \
    IMPL(tomcrypt,   __VA_ARGS__)

struct hash_impl implementations[] = {
    IMPL_ALL("MD5",        md5,       "aa26ff5b895356bcffd9292ba9f89e66")
    IMPL_ALL("SHA-1",      sha1,      "1fd8bd1fa02f5b0fe916b0d71750726b096c5744")
    IMPL_ALL("SHA-256",    sha256,    "14028ac673b3087e51a1d407fbf0df4deeec8f217119e13b07bf2138f93db8c5")
    IMPL_ALL("SHA-512",    sha512,    "3afdd44a80d99af15c87bd724cb717243193767835ce866dd5d58c02d674bb57"
                                      "7c25b9e118c200a189fcd5a01ef106a4e200061f3e97dbf50ba065745fd46bef")
    IMPL(lavu,     "RIPEMD-128", ripemd128, "9ab8bfba2ddccc5d99c9d4cdfb844a5f")
    IMPL(tomcrypt, "RIPEMD-128", ripemd128, "9ab8bfba2ddccc5d99c9d4cdfb844a5f")
    IMPL_ALL("RIPEMD-160", ripemd160, "62a5321e4fc8784903bb43ab7752c75f8b25af00")
    IMPL_ALL("AES-128-ECB",aes128,    "crc:ff6bc888")
    IMPL_ALL("AES-192-ECB",aes192,    "crc:1022815b")
    IMPL_ALL("AES-256-ECB",aes256,    "crc:792e4e8a")
    IMPL_ALL("AES-128-CBC",aes128cbc, "crc:0efebabe")
    IMPL_ALL("AES-192-CBC",aes192cbc, "crc:ee2e34e8")
    IMPL_ALL("AES-256-CBC",aes256cbc, "crc:0c9b875c")
    IMPL_ALL("CAMELLIA",   camellia,  "crc:7abb59a7")
    IMPL_ALL("CAST-128",   cast128,   "crc:456aa584")
    IMPL_ALL("BLOWFISH",   blowfish,  "crc:33e8aa74")
    IMPL(lavu,     "TWOFISH", twofish, "crc:9edbd5c1")
    IMPL(gcrypt,   "TWOFISH", twofish, "crc:9edbd5c1")
    IMPL(tomcrypt, "TWOFISH", twofish, "crc:9edbd5c1")
    IMPL(lavu,     "RC4",     rc4,     "crc:538d37b2")
    IMPL(crypto,   "RC4",     rc4,     "crc:538d37b2")
    IMPL(lavu,     "XTEA",    xtea,    "crc:931fc270")
    IMPL(tomcrypt, "XTEA",    xtea,    "crc:931fc270")
};

int main(int argc, char **argv)
{
    uint8_t *input = av_malloc(MAX_INPUT_SIZE * 2);
    uint8_t *output = input + MAX_INPUT_SIZE;
    unsigned i, impl, size;
    int opt;

#if (USE_EXT_LIBS) & USE_tomcrypt
    register_cipher(&aes_desc);
#endif

    while ((opt = getopt(argc, argv, "hl:a:r:")) != -1) {
        switch (opt) {
        case 'l':
            enabled_libs = optarg;
            break;
        case 'a':
            enabled_algos = optarg;
            break;
        case 'r':
            specified_runs = strtol(optarg, NULL, 0);
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: %s [-l libs] [-a algos] [-r runs]\n",
                    argv[0]);
            if ((USE_EXT_LIBS)) {
                char buf[1024];
                snprintf(buf, sizeof(buf), "%s%s%s",
                         ((USE_EXT_LIBS) & USE_crypto)   ? "+crypto"   : "",
                         ((USE_EXT_LIBS) & USE_gcrypt)   ? "+gcrypt"   : "",
                         ((USE_EXT_LIBS) & USE_tomcrypt) ? "+tomcrypt" : "");
                fprintf(stderr, "Built with the following external libraries:\n"
                        "make VERSUS=%s\n", buf + 1);
            } else {
                fprintf(stderr, "Built without external libraries; use\n"
                        "make VERSUS=crypto+gcrypt+tomcrypt tools/crypto_bench\n"
                        "to enable them.\n");
            }
            exit(opt != 'h');
        }
    }

    if (!input)
        fatal_error("out of memory");
    for (i = 0; i < MAX_INPUT_SIZE; i += 4)
        AV_WB32(input + i, i);

    size = MAX_INPUT_SIZE;
    for (impl = 0; impl < FF_ARRAY_ELEMS(implementations); impl++)
        run_implementation(input, output, &implementations[impl], size);

    av_free(input);

    return 0;
}
