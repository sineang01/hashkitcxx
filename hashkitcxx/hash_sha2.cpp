/*
 * HashKitCXX
 *
 * Copyright (c) 2018, Simone Angeloni
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Thomas J Bradley nor the names of its contributors may
 *   be used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ----------------------------------------------------------------------------------
 *
 * The HashKitCXX namespace sha2 is based on original work from Olivier Gay
 * Copyright: 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * License: 3-Clause BSD
 * Description: "Fast software implementation in C of the FIPS 180-2 hash algorithms
 *   SHA-224, SHA-256, SHA-384 and SHA-512"
 * Resource link: https://github.com/ogay/sha2

 * ----------------------------------------------------------------------------------
 *
 * Name of Standard: Secure Hash Standard (SHS) (FIPS PUB 180-4)
 * Category of Standard: Computer Security Standard, Cryptography
 * Date Published: August 2015
 * Author(s): National Institute of Standards and Technology
 * Resource link: https://csrc.nist.gov/publications/detail/fips/180/4/final
 */

#include "hash_sha2.hpp"
#include <cstdio>
#include <cstring>

#if defined(HASHLIBCXX_ASSERT)
#    undef HASHLIBCXX_ASSERT
#endif
#if defined(HASHLIBCXX_STD_ASSERT)
#    include <cassert>
#    define HASHLIBCXX_ASSERT assert
#else
#    define HASHLIBCXX_ASSERT(x)
#endif

#if defined(SHFR)
#    undef SHFR
#endif
#define SHFR(x, n) ((x) >> (n))

#if defined(ROTR)
#    undef ROTR
#endif
#define ROTR(x, n) (((x) >> (n)) | ((x) << ((sizeof(x) << 3) - (n))))

#if defined(CH)
#    undef CH
#endif
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))

#if defined(MAJ)
#    undef MAJ
#endif
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#if defined(SHA256_F1)
#    undef SHA256_F1
#endif
#define SHA256_F1(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))

#if defined(SHA256_F2)
#    undef SHA256_F2
#endif
#define SHA256_F2(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

#if defined(SHA256_F3)
#    undef SHA256_F3
#endif
#define SHA256_F3(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHFR(x, 3))

#if defined(SHA256_F4)
#    undef SHA256_F4
#endif
#define SHA256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

#if defined(SHA512_F1)
#    undef SHA512_F1
#endif
#define SHA512_F1(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))

#if defined(SHA512_F2)
#    undef SHA512_F2
#endif
#define SHA512_F2(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))

#if defined(SHA512_F3)
#    undef SHA512_F3
#endif
#define SHA512_F3(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHFR(x, 7))

#if defined(SHA512_F4)
#    undef SHA512_F4
#endif
#define SHA512_F4(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x, 6))

#if defined(UNPACK32)
#    undef UNPACK32
#endif
#define UNPACK32(x, str)                                                                           \
    {                                                                                              \
        *((str) + 3) = static_cast<uint8_t>((x));                                                  \
        *((str) + 2) = static_cast<uint8_t>((x) >> 8);                                             \
        *((str) + 1) = static_cast<uint8_t>((x) >> 16);                                            \
        *((str) + 0) = static_cast<uint8_t>((x) >> 24);                                            \
    }

#if defined(PACK32)
#    undef PACK32
#endif
#define PACK32(str, x)                                                                             \
    {                                                                                              \
        *(x) = (static_cast<uint32_t>(*((str) + 3))) |                                             \
               (static_cast<uint32_t>(*((str) + 2)) << 8) |                                        \
               (static_cast<uint32_t>(*((str) + 1)) << 16) |                                       \
               (static_cast<uint32_t>(*((str) + 0)) << 24);                                        \
    }

#if defined(UNPACK64)
#    undef UNPACK64
#endif
#define UNPACK64(x, str)                                                                           \
    {                                                                                              \
        *((str) + 7) = static_cast<uint8_t>((x));                                                  \
        *((str) + 6) = static_cast<uint8_t>((x) >> 8);                                             \
        *((str) + 5) = static_cast<uint8_t>((x) >> 16);                                            \
        *((str) + 4) = static_cast<uint8_t>((x) >> 24);                                            \
        *((str) + 3) = static_cast<uint8_t>((x) >> 32);                                            \
        *((str) + 2) = static_cast<uint8_t>((x) >> 40);                                            \
        *((str) + 1) = static_cast<uint8_t>((x) >> 48);                                            \
        *((str) + 0) = static_cast<uint8_t>((x) >> 56);                                            \
    }

#if defined(PACK64)
#    undef PACK64
#endif
#define PACK64(str, x)                                                                             \
    {                                                                                              \
        *(x) = (static_cast<uint64_t>(*((str) + 7))) |                                             \
               (static_cast<uint64_t>(*((str) + 6)) << 8) |                                        \
               (static_cast<uint64_t>(*((str) + 5)) << 16) |                                       \
               (static_cast<uint64_t>(*((str) + 4)) << 24) |                                       \
               (static_cast<uint64_t>(*((str) + 3)) << 32) |                                       \
               (static_cast<uint64_t>(*((str) + 2)) << 40) |                                       \
               (static_cast<uint64_t>(*((str) + 1)) << 48) |                                       \
               (static_cast<uint64_t>(*((str) + 0)) << 56);                                        \
    }

#if defined(SHA256_SCR)
#    undef SHA256_SCR
#endif
#define SHA256_SCR(i)                                                                              \
    {                                                                                              \
        w[i] = SHA256_F4(w[(i)-2]) + w[(i)-7] + SHA256_F3(w[(i)-15]) + w[(i)-16];                  \
    }

#if defined(SHA512_SCR)
#    undef SHA512_SCR
#endif
#define SHA512_SCR(i)                                                                              \
    {                                                                                              \
        w[i] = SHA512_F4(w[(i)-2]) + w[(i)-7] + SHA512_F3(w[(i)-15]) + w[(i)-16];                  \
    }

#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wunused-macros"
#endif

#if defined(SHA256_EXP)
#    undef SHA256_EXP
#endif
#define SHA256_EXP(a, b, c, d, e, f, g, h, j)                                                      \
    {                                                                                              \
        t1 = wv[h] + SHA256_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) + sha256_k[j] + w[j];              \
        t2 = SHA256_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);                                          \
        wv[d] += t1;                                                                               \
        wv[h] = t1 + t2;                                                                           \
    }

#if defined(SHA512_EXP)
#    undef SHA512_EXP
#endif
#define SHA512_EXP(a, b, c, d, e, f, g, h, j)                                                      \
    {                                                                                              \
        t1 = wv[h] + SHA512_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) + sha512_k[j] + w[j];              \
        t2 = SHA512_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);                                          \
        wv[d] += t1;                                                                               \
        wv[h] = t1 + t2;                                                                           \
    }

#if defined(__clang__)
#    pragma clang diagnostic pop
#endif

namespace hashkitcxx {
    namespace sha2 {

        static constexpr std::array<uint32_t, 8> sha224_h0 = {0xc1059ed8U,
                                                              0x367cd507U,
                                                              0x3070dd17U,
                                                              0xf70e5939U,
                                                              0xffc00b31U,
                                                              0x68581511U,
                                                              0x64f98fa7U,
                                                              0xbefa4fa4U};

        static constexpr std::array<uint32_t, 8> sha256_h0 = {0x6a09e667U,
                                                              0xbb67ae85U,
                                                              0x3c6ef372U,
                                                              0xa54ff53aU,
                                                              0x510e527fU,
                                                              0x9b05688cU,
                                                              0x1f83d9abU,
                                                              0x5be0cd19U};

        static constexpr std::array<uint64_t, 8> sha384_h0 = {0xcbbb9d5dc1059ed8ULL,
                                                              0x629a292a367cd507ULL,
                                                              0x9159015a3070dd17ULL,
                                                              0x152fecd8f70e5939ULL,
                                                              0x67332667ffc00b31ULL,
                                                              0x8eb44a8768581511ULL,
                                                              0xdb0c2e0d64f98fa7ULL,
                                                              0x47b5481dbefa4fa4ULL};

        static constexpr std::array<uint64_t, 8> sha512_h0 = {0x6a09e667f3bcc908ULL,
                                                              0xbb67ae8584caa73bULL,
                                                              0x3c6ef372fe94f82bULL,
                                                              0xa54ff53a5f1d36f1ULL,
                                                              0x510e527fade682d1ULL,
                                                              0x9b05688c2b3e6c1fULL,
                                                              0x1f83d9abfb41bd6bULL,
                                                              0x5be0cd19137e2179ULL};

        static constexpr std::array<uint64_t, 8> sha512_224_h0 = {0x8c3d37c819544da2ULL,
                                                                  0x73e1996689dcd4d6ULL,
                                                                  0x1dfab7ae32ff9c82ULL,
                                                                  0x679dd514582f9fcfULL,
                                                                  0x0f6d2b697bd44da8ULL,
                                                                  0x77e36f7304c48942ULL,
                                                                  0x3f9d85a86a1d36c8ULL,
                                                                  0x1112e6ad91d692a1ULL};

        static constexpr std::array<uint64_t, 8> sha512_256_h0 = {0x22312194fc2bf72cULL,
                                                                  0x9f555fa3c84c64c2ULL,
                                                                  0x2393b86b6f53b151ULL,
                                                                  0x963877195940eabdULL,
                                                                  0x96283ee2a88effe3ULL,
                                                                  0xbe5e1e2553863992ULL,
                                                                  0x2b0199fc2c85b8aaULL,
                                                                  0x0eb72ddc81c52ca2ULL};

        static constexpr std::array<uint32_t, 64> sha256_k =
            {0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
             0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
             0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
             0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
             0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
             0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
             0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
             0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
             0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
             0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
             0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

        static const std::array<uint64_t, 80> sha512_k =
            {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
             0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
             0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
             0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
             0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
             0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
             0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
             0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
             0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
             0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
             0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
             0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
             0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
             0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
             0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
             0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
             0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
             0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
             0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
             0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
             0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
             0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
             0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
             0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
             0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
             0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
             0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

        template<class THash>
        void to_hex(THash & h,
                    const unsigned char * message,
                    size_t len,
                    char * digest_printable) noexcept
        {
            HASHLIBCXX_ASSERT(message);
            HASHLIBCXX_ASSERT(digest_printable);

            unsigned char digest[THash::s_digest_size]{};
            h.hash(message, len, digest);

            for (size_t i{0}; i < THash::s_digest_size; ++i)
            {
#if defined(WIN32) && !defined(_CRT_SECURE_NO_WARNINGS)
                sprintf_s(digest_printable + i * 2, 3, "%02x", digest[i]);
#else
                sprintf(digest_printable + i * 2, "%02x", digest[i]);
#endif
            }
        }

        template<typename TContext>
        void sha256_transform(TContext & ctx,
                              const unsigned char * message,
                              size_t block_nb) noexcept
        {
            HASHLIBCXX_ASSERT(message);

            uint32_t w[64];
            uint32_t wv[8];
            uint32_t t1, t2;
            const unsigned char * sub_block;

#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
            size_t j;
#endif

            for (size_t i{0}; i < block_nb; ++i)
            {
                sub_block = message + (i << 6);

#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
                for (j = 0; j < 16; ++j)
                {
                    PACK32(&sub_block[j << 2], &w[j]);
                }

                for (j = 16; j < 64; ++j)
                {
                    SHA256_SCR(j);
                }

                for (j = 0; j < 8; ++j)
                {
                    wv[j] = ctx.h[j];
                }

                for (j = 0; j < 64; ++j)
                {
                    t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[j] + w[j];
                    t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
                    wv[7] = wv[6];
                    wv[6] = wv[5];
                    wv[5] = wv[4];
                    wv[4] = wv[3] + t1;
                    wv[3] = wv[2];
                    wv[2] = wv[1];
                    wv[1] = wv[0];
                    wv[0] = t1 + t2;
                }

                for (j = 0; j < 8; ++j)
                {
                    ctx.h[j] += wv[j];
                }
#else
                PACK32(&sub_block[0], &w[0]);
                PACK32(&sub_block[4], &w[1]);
                PACK32(&sub_block[8], &w[2]);
                PACK32(&sub_block[12], &w[3]);
                PACK32(&sub_block[16], &w[4]);
                PACK32(&sub_block[20], &w[5]);
                PACK32(&sub_block[24], &w[6]);
                PACK32(&sub_block[28], &w[7]);
                PACK32(&sub_block[32], &w[8]);
                PACK32(&sub_block[36], &w[9]);
                PACK32(&sub_block[40], &w[10]);
                PACK32(&sub_block[44], &w[11]);
                PACK32(&sub_block[48], &w[12]);
                PACK32(&sub_block[52], &w[13]);
                PACK32(&sub_block[56], &w[14]);
                PACK32(&sub_block[60], &w[15]);

                SHA256_SCR(16);
                SHA256_SCR(17);
                SHA256_SCR(18);
                SHA256_SCR(19);
                SHA256_SCR(20);
                SHA256_SCR(21);
                SHA256_SCR(22);
                SHA256_SCR(23);
                SHA256_SCR(24);
                SHA256_SCR(25);
                SHA256_SCR(26);
                SHA256_SCR(27);
                SHA256_SCR(28);
                SHA256_SCR(29);
                SHA256_SCR(30);
                SHA256_SCR(31);
                SHA256_SCR(32);
                SHA256_SCR(33);
                SHA256_SCR(34);
                SHA256_SCR(35);
                SHA256_SCR(36);
                SHA256_SCR(37);
                SHA256_SCR(38);
                SHA256_SCR(39);
                SHA256_SCR(40);
                SHA256_SCR(41);
                SHA256_SCR(42);
                SHA256_SCR(43);
                SHA256_SCR(44);
                SHA256_SCR(45);
                SHA256_SCR(46);
                SHA256_SCR(47);
                SHA256_SCR(48);
                SHA256_SCR(49);
                SHA256_SCR(50);
                SHA256_SCR(51);
                SHA256_SCR(52);
                SHA256_SCR(53);
                SHA256_SCR(54);
                SHA256_SCR(55);
                SHA256_SCR(56);
                SHA256_SCR(57);
                SHA256_SCR(58);
                SHA256_SCR(59);
                SHA256_SCR(60);
                SHA256_SCR(61);
                SHA256_SCR(62);
                SHA256_SCR(63);

                wv[0] = ctx.h[0];
                wv[1] = ctx.h[1];
                wv[2] = ctx.h[2];
                wv[3] = ctx.h[3];
                wv[4] = ctx.h[4];
                wv[5] = ctx.h[5];
                wv[6] = ctx.h[6];
                wv[7] = ctx.h[7];

                SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 0);
                SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 1);
                SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 2);
                SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 3);
                SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 4);
                SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 5);
                SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 6);
                SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 7);
                SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 8);
                SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 9);
                SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 10);
                SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 11);
                SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 12);
                SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 13);
                SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 14);
                SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 15);
                SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 16);
                SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 17);
                SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 18);
                SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 19);
                SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 20);
                SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 21);
                SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 22);
                SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 23);
                SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 24);
                SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 25);
                SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 26);
                SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 27);
                SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 28);
                SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 29);
                SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 30);
                SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 31);
                SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 32);
                SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 33);
                SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 34);
                SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 35);
                SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 36);
                SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 37);
                SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 38);
                SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 39);
                SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 40);
                SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 41);
                SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 42);
                SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 43);
                SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 44);
                SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 45);
                SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 46);
                SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 47);
                SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 48);
                SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 49);
                SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 50);
                SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 51);
                SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 52);
                SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 53);
                SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 54);
                SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 55);
                SHA256_EXP(0, 1, 2, 3, 4, 5, 6, 7, 56);
                SHA256_EXP(7, 0, 1, 2, 3, 4, 5, 6, 57);
                SHA256_EXP(6, 7, 0, 1, 2, 3, 4, 5, 58);
                SHA256_EXP(5, 6, 7, 0, 1, 2, 3, 4, 59);
                SHA256_EXP(4, 5, 6, 7, 0, 1, 2, 3, 60);
                SHA256_EXP(3, 4, 5, 6, 7, 0, 1, 2, 61);
                SHA256_EXP(2, 3, 4, 5, 6, 7, 0, 1, 62);
                SHA256_EXP(1, 2, 3, 4, 5, 6, 7, 0, 63);

                ctx.h[0] += wv[0];
                ctx.h[1] += wv[1];
                ctx.h[2] += wv[2];
                ctx.h[3] += wv[3];
                ctx.h[4] += wv[4];
                ctx.h[5] += wv[5];
                ctx.h[6] += wv[6];
                ctx.h[7] += wv[7];
#endif
            }
        }

        template<typename TContext>
        void sha512_transform(TContext & ctx,
                              const unsigned char * message,
                              size_t block_nb) noexcept
        {
            HASHLIBCXX_ASSERT(message);

            uint64_t w[80];
            uint64_t wv[8];
            uint64_t t1, t2;
            const unsigned char * sub_block;
            size_t j;

            for (size_t i{0}; i < block_nb; ++i)
            {
                sub_block = message + (i << 7);

#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
                for (j = 0; j < 16; ++j)
                {
                    PACK64(&sub_block[j << 3], &w[j]);
                }

                for (j = 16; j < 80; ++j)
                {
                    SHA512_SCR(j);
                }

                for (j = 0; j < 8; ++j)
                {
                    wv[j] = ctx.h[j];
                }

                for (j = 0; j < 80; ++j)
                {
                    t1 = wv[7] + SHA512_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha512_k[j] + w[j];
                    t2 = SHA512_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
                    wv[7] = wv[6];
                    wv[6] = wv[5];
                    wv[5] = wv[4];
                    wv[4] = wv[3] + t1;
                    wv[3] = wv[2];
                    wv[2] = wv[1];
                    wv[1] = wv[0];
                    wv[0] = t1 + t2;
                }

                for (j = 0; j < 8; ++j)
                {
                    ctx.h[j] += wv[j];
                }
#else
                PACK64(&sub_block[0], &w[0]);
                PACK64(&sub_block[8], &w[1]);
                PACK64(&sub_block[16], &w[2]);
                PACK64(&sub_block[24], &w[3]);
                PACK64(&sub_block[32], &w[4]);
                PACK64(&sub_block[40], &w[5]);
                PACK64(&sub_block[48], &w[6]);
                PACK64(&sub_block[56], &w[7]);
                PACK64(&sub_block[64], &w[8]);
                PACK64(&sub_block[72], &w[9]);
                PACK64(&sub_block[80], &w[10]);
                PACK64(&sub_block[88], &w[11]);
                PACK64(&sub_block[96], &w[12]);
                PACK64(&sub_block[104], &w[13]);
                PACK64(&sub_block[112], &w[14]);
                PACK64(&sub_block[120], &w[15]);

                SHA512_SCR(16);
                SHA512_SCR(17);
                SHA512_SCR(18);
                SHA512_SCR(19);
                SHA512_SCR(20);
                SHA512_SCR(21);
                SHA512_SCR(22);
                SHA512_SCR(23);
                SHA512_SCR(24);
                SHA512_SCR(25);
                SHA512_SCR(26);
                SHA512_SCR(27);
                SHA512_SCR(28);
                SHA512_SCR(29);
                SHA512_SCR(30);
                SHA512_SCR(31);
                SHA512_SCR(32);
                SHA512_SCR(33);
                SHA512_SCR(34);
                SHA512_SCR(35);
                SHA512_SCR(36);
                SHA512_SCR(37);
                SHA512_SCR(38);
                SHA512_SCR(39);
                SHA512_SCR(40);
                SHA512_SCR(41);
                SHA512_SCR(42);
                SHA512_SCR(43);
                SHA512_SCR(44);
                SHA512_SCR(45);
                SHA512_SCR(46);
                SHA512_SCR(47);
                SHA512_SCR(48);
                SHA512_SCR(49);
                SHA512_SCR(50);
                SHA512_SCR(51);
                SHA512_SCR(52);
                SHA512_SCR(53);
                SHA512_SCR(54);
                SHA512_SCR(55);
                SHA512_SCR(56);
                SHA512_SCR(57);
                SHA512_SCR(58);
                SHA512_SCR(59);
                SHA512_SCR(60);
                SHA512_SCR(61);
                SHA512_SCR(62);
                SHA512_SCR(63);
                SHA512_SCR(64);
                SHA512_SCR(65);
                SHA512_SCR(66);
                SHA512_SCR(67);
                SHA512_SCR(68);
                SHA512_SCR(69);
                SHA512_SCR(70);
                SHA512_SCR(71);
                SHA512_SCR(72);
                SHA512_SCR(73);
                SHA512_SCR(74);
                SHA512_SCR(75);
                SHA512_SCR(76);
                SHA512_SCR(77);
                SHA512_SCR(78);
                SHA512_SCR(79);

                wv[0] = ctx.h[0];
                wv[1] = ctx.h[1];
                wv[2] = ctx.h[2];
                wv[3] = ctx.h[3];
                wv[4] = ctx.h[4];
                wv[5] = ctx.h[5];
                wv[6] = ctx.h[6];
                wv[7] = ctx.h[7];

                j = 0;

                do
                {
                    SHA512_EXP(0, 1, 2, 3, 4, 5, 6, 7, j);
                    ++j;
                    SHA512_EXP(7, 0, 1, 2, 3, 4, 5, 6, j);
                    ++j;
                    SHA512_EXP(6, 7, 0, 1, 2, 3, 4, 5, j);
                    ++j;
                    SHA512_EXP(5, 6, 7, 0, 1, 2, 3, 4, j);
                    ++j;
                    SHA512_EXP(4, 5, 6, 7, 0, 1, 2, 3, j);
                    ++j;
                    SHA512_EXP(3, 4, 5, 6, 7, 0, 1, 2, j);
                    ++j;
                    SHA512_EXP(2, 3, 4, 5, 6, 7, 0, 1, j);
                    ++j;
                    SHA512_EXP(1, 2, 3, 4, 5, 6, 7, 0, j);
                    ++j;
                } while (j < 80);

                ctx.h[0] += wv[0];
                ctx.h[1] += wv[1];
                ctx.h[2] += wv[2];
                ctx.h[3] += wv[3];
                ctx.h[4] += wv[4];
                ctx.h[5] += wv[5];
                ctx.h[6] += wv[6];
                ctx.h[7] += wv[7];
#endif
            }
        }

        // ------------------------------------------------------------------
        // --- sha-256 ------------------------------------------------------

        void sha256::hash_printable(const unsigned char * message,
                                    size_t len,
                                    char * digest_printable) noexcept
        {
            to_hex(*this, message, len, digest_printable);
        }

        void sha256::init() noexcept
        {
#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
            for (uint8_t i{0}; i < 8; ++i)
            {
                m_ctx.h[i] = sha256_h0[i];
            }
#else
            m_ctx.h[0] = sha256_h0[0];
            m_ctx.h[1] = sha256_h0[1];
            m_ctx.h[2] = sha256_h0[2];
            m_ctx.h[3] = sha256_h0[3];
            m_ctx.h[4] = sha256_h0[4];
            m_ctx.h[5] = sha256_h0[5];
            m_ctx.h[6] = sha256_h0[6];
            m_ctx.h[7] = sha256_h0[7];
#endif

            m_ctx.len = 0;
            m_ctx.tot_len = 0;
        }

        void sha256::update(const unsigned char * message, size_t len) noexcept
        {
            HASHLIBCXX_ASSERT(message);

            size_t tmp_len{s_block_size - m_ctx.len};
            size_t rem_len{len < tmp_len ? len : tmp_len};

            std::memcpy(&m_ctx.block[m_ctx.len], message, rem_len);

            if (m_ctx.len + len < s_block_size)
            {
                m_ctx.len += len;
                return;
            }

            size_t new_len{len - rem_len};
            size_t block_nb{new_len / s_block_size};

            const unsigned char * shifted_message{message + rem_len};

            sha256_transform(m_ctx, m_ctx.block, 1);
            sha256_transform(m_ctx, shifted_message, block_nb);

            rem_len = new_len % s_block_size;

            std::memcpy(m_ctx.block, &shifted_message[block_nb << 6], rem_len);

            m_ctx.len = rem_len;
            m_ctx.tot_len += (block_nb + 1) << 6;
        }

        void sha256::complete(unsigned char * digest) noexcept
        {
            HASHLIBCXX_ASSERT(digest);

            size_t block_nb{
                (1U + static_cast<unsigned int>((s_block_size - 9U) < (m_ctx.len % s_block_size)))};
            uint64_t len_b{(static_cast<uint64_t>(m_ctx.tot_len) + static_cast<uint64_t>(m_ctx.len))
                           << 3};
            size_t pm_len{block_nb << 6};

            std::memset(m_ctx.block + m_ctx.len, 0, pm_len - m_ctx.len);
            m_ctx.block[m_ctx.len] = 0x80;
            UNPACK64(len_b, m_ctx.block + pm_len - 8);

            sha256_transform(m_ctx, m_ctx.block, block_nb);

#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
            for (uint8_t i{0}; i < 8; ++i)
            {
                UNPACK32(m_ctx.h[i], &digest[i << 2]);
            }
#else
            UNPACK32(m_ctx.h[0], &digest[0]);
            UNPACK32(m_ctx.h[1], &digest[4]);
            UNPACK32(m_ctx.h[2], &digest[8]);
            UNPACK32(m_ctx.h[3], &digest[12]);
            UNPACK32(m_ctx.h[4], &digest[16]);
            UNPACK32(m_ctx.h[5], &digest[20]);
            UNPACK32(m_ctx.h[6], &digest[24]);
            UNPACK32(m_ctx.h[7], &digest[28]);
#endif
        }

        // ------------------------------------------------------------------
        // --- sha-512 ------------------------------------------------------

        sha512::sha512() : m_h0{sha512_h0} {}
        sha512::sha512(const std::array<uint64_t, 8> & h0) : m_h0{h0} {}

        void sha512::hash_printable(const unsigned char * message,
                                    size_t len,
                                    char * digest_printable) noexcept
        {
            to_hex(*this, message, len, digest_printable);
        }

        void sha512::init() noexcept
        {
#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
            for (uint8_t i{0}; i < 8; ++i)
            {
                m_ctx.h[i] = m_h0[i];
            }
#else
            m_ctx.h[0] = m_h0[0];
            m_ctx.h[1] = m_h0[1];
            m_ctx.h[2] = m_h0[2];
            m_ctx.h[3] = m_h0[3];
            m_ctx.h[4] = m_h0[4];
            m_ctx.h[5] = m_h0[5];
            m_ctx.h[6] = m_h0[6];
            m_ctx.h[7] = m_h0[7];
#endif

            m_ctx.len = 0;
            m_ctx.tot_len = 0;
        }

        void sha512::update(const unsigned char * message, size_t len) noexcept
        {
            HASHLIBCXX_ASSERT(message);

            size_t tmp_len{s_block_size - m_ctx.len};
            size_t rem_len{len < tmp_len ? len : tmp_len};

            std::memcpy(&m_ctx.block[m_ctx.len], message, rem_len);

            if (m_ctx.len + len < s_block_size)
            {
                m_ctx.len += len;
                return;
            }

            size_t new_len{len - rem_len};
            size_t block_nb{new_len / s_block_size};

            const unsigned char * shifted_message{message + rem_len};

            sha512_transform(m_ctx, m_ctx.block, 1);
            sha512_transform(m_ctx, shifted_message, block_nb);

            rem_len = new_len % s_block_size;

            std::memcpy(m_ctx.block, &shifted_message[block_nb << 7], rem_len);

            m_ctx.len = rem_len;
            m_ctx.tot_len += (block_nb + 1) << 7;
        }

        void sha512::complete(unsigned char * digest) noexcept
        {
            HASHLIBCXX_ASSERT(digest);

            size_t block_nb{
                1U + static_cast<unsigned int>((s_block_size - 17U) < (m_ctx.len % s_block_size))};
            uint64_t len_b{(static_cast<uint64_t>(m_ctx.tot_len) + static_cast<uint64_t>(m_ctx.len))
                           << 3};
            size_t pm_len{block_nb << 7};

            std::memset(m_ctx.block + m_ctx.len, 0, pm_len - m_ctx.len);
            m_ctx.block[m_ctx.len] = 0x80;
            UNPACK64(len_b, m_ctx.block + pm_len - 8);

            sha512_transform(m_ctx, m_ctx.block, block_nb);

#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
            for (uint8_t i{0}; i < 8; ++i)
            {
                UNPACK64(m_ctx.h[i], &digest[i << 3]);
            }
#else
            UNPACK64(m_ctx.h[0], &digest[0]);
            UNPACK64(m_ctx.h[1], &digest[8]);
            UNPACK64(m_ctx.h[2], &digest[16]);
            UNPACK64(m_ctx.h[3], &digest[24]);
            UNPACK64(m_ctx.h[4], &digest[32]);
            UNPACK64(m_ctx.h[5], &digest[40]);
            UNPACK64(m_ctx.h[6], &digest[48]);
            UNPACK64(m_ctx.h[7], &digest[56]);
#endif
        }

        // ------------------------------------------------------------------
        // --- sha-512/224 --------------------------------------------------

        void sha512_224::hash_printable(const unsigned char * message,
                                        size_t len,
                                        char * digest_printable) noexcept
        {
            to_hex(*this, message, len, digest_printable);
        }

        void sha512_224::hash(const unsigned char * message,
                              size_t len,
                              unsigned char * digest) noexcept
        {
            unsigned char sha512_digest[sha512::s_digest_size];
            sha512 h(sha512_224_h0);
            h.hash(message, len, sha512_digest);
            std::memcpy(digest, sha512_digest, s_digest_size);
        }

        // ------------------------------------------------------------------
        // --- sha-512/256 --------------------------------------------------

        void sha512_256::hash_printable(const unsigned char * message,
                                        size_t len,
                                        char * digest_printable) noexcept
        {
            to_hex(*this, message, len, digest_printable);
        }

        void sha512_256::hash(const unsigned char * message,
                              size_t len,
                              unsigned char * digest) noexcept
        {
            unsigned char sha512_digest[sha512::s_digest_size];
            sha512 h(sha512_256_h0);
            h.hash(message, len, sha512_digest);
            std::memcpy(digest, sha512_digest, s_digest_size);
        }

        // ------------------------------------------------------------------
        // --- sha-384 ------------------------------------------------------

        void sha384::hash_printable(const unsigned char * message,
                                    size_t len,
                                    char * digest_printable) noexcept
        {
            to_hex(*this, message, len, digest_printable);
        }

        void sha384::init() noexcept
        {
#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
            for (uint8_t i{0}; i < 8; ++i)
            {
                m_ctx.h[i] = sha384_h0[i];
            }
#else
            m_ctx.h[0] = sha384_h0[0];
            m_ctx.h[1] = sha384_h0[1];
            m_ctx.h[2] = sha384_h0[2];
            m_ctx.h[3] = sha384_h0[3];
            m_ctx.h[4] = sha384_h0[4];
            m_ctx.h[5] = sha384_h0[5];
            m_ctx.h[6] = sha384_h0[6];
            m_ctx.h[7] = sha384_h0[7];
#endif

            m_ctx.len = 0;
            m_ctx.tot_len = 0;
        }

        void sha384::update(const unsigned char * message, size_t len) noexcept
        {
            HASHLIBCXX_ASSERT(message);

            size_t tmp_len{s_block_size - m_ctx.len};
            size_t rem_len{len < tmp_len ? len : tmp_len};

            std::memcpy(&m_ctx.block[m_ctx.len], message, rem_len);

            if (m_ctx.len + len < s_block_size)
            {
                m_ctx.len += len;
                return;
            }

            size_t new_len{len - rem_len};
            size_t block_nb{new_len / s_block_size};

            const unsigned char * shifted_message{message + rem_len};

            sha512_transform(m_ctx, m_ctx.block, 1);
            sha512_transform(m_ctx, shifted_message, block_nb);

            rem_len = new_len % s_block_size;

            std::memcpy(m_ctx.block, &shifted_message[block_nb << 7], rem_len);

            m_ctx.len = rem_len;
            m_ctx.tot_len += (block_nb + 1) << 7;
        }

        void sha384::complete(unsigned char * digest) noexcept
        {
            HASHLIBCXX_ASSERT(digest);

            size_t block_nb{(
                1U + static_cast<unsigned int>((s_block_size - 17U) < (m_ctx.len % s_block_size)))};
            uint64_t len_b{(static_cast<uint64_t>(m_ctx.tot_len) + static_cast<uint64_t>(m_ctx.len))
                           << 3};
            size_t pm_len{block_nb << 7};

            std::memset(m_ctx.block + m_ctx.len, 0, pm_len - m_ctx.len);
            m_ctx.block[m_ctx.len] = 0x80;
            UNPACK64(len_b, m_ctx.block + pm_len - 8);

            sha512_transform(m_ctx, m_ctx.block, block_nb);

#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
            for (uint8_t i{0}; i < 6; ++i)
            {
                UNPACK64(m_ctx.h[i], &digest[i << 3]);
            }
#else
            UNPACK64(m_ctx.h[0], &digest[0]);
            UNPACK64(m_ctx.h[1], &digest[8]);
            UNPACK64(m_ctx.h[2], &digest[16]);
            UNPACK64(m_ctx.h[3], &digest[24]);
            UNPACK64(m_ctx.h[4], &digest[32]);
            UNPACK64(m_ctx.h[5], &digest[40]);
#endif
        }

        // ------------------------------------------------------------------
        // --- sha-224 ------------------------------------------------------

        void sha224::hash_printable(const unsigned char * message,
                                    size_t len,
                                    char * digest_printable) noexcept
        {
            to_hex(*this, message, len, digest_printable);
        }

        void sha224::init() noexcept
        {
#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
            for (uint8_t i{0}; i < 8; ++i)
            {
                m_ctx.h[i] = sha224_h0[i];
            }
#else
            m_ctx.h[0] = sha224_h0[0];
            m_ctx.h[1] = sha224_h0[1];
            m_ctx.h[2] = sha224_h0[2];
            m_ctx.h[3] = sha224_h0[3];
            m_ctx.h[4] = sha224_h0[4];
            m_ctx.h[5] = sha224_h0[5];
            m_ctx.h[6] = sha224_h0[6];
            m_ctx.h[7] = sha224_h0[7];
#endif

            m_ctx.len = 0;
            m_ctx.tot_len = 0;
        }

        void sha224::update(const unsigned char * message, size_t len) noexcept
        {
            HASHLIBCXX_ASSERT(message);

            size_t tmp_len{s_block_size - m_ctx.len};
            size_t rem_len{len < tmp_len ? len : tmp_len};

            std::memcpy(&m_ctx.block[m_ctx.len], message, rem_len);

            if (m_ctx.len + len < s_block_size)
            {
                m_ctx.len += len;
                return;
            }

            size_t new_len{len - rem_len};
            size_t block_nb{new_len / s_block_size};

            const unsigned char * shifted_message{message + rem_len};

            sha256_transform(m_ctx, m_ctx.block, 1);
            sha256_transform(m_ctx, shifted_message, block_nb);

            rem_len = new_len % s_block_size;

            std::memcpy(m_ctx.block, &shifted_message[block_nb << 6], rem_len);

            m_ctx.len = rem_len;
            m_ctx.tot_len += (block_nb + 1) << 6;
        }

        void sha224::complete(unsigned char * digest) noexcept
        {
            HASHLIBCXX_ASSERT(digest);

            size_t block_nb{
                (1U + static_cast<unsigned int>((s_block_size - 9U) < (m_ctx.len % s_block_size)))};
            uint64_t len_b{(static_cast<uint64_t>(m_ctx.tot_len) + static_cast<uint64_t>(m_ctx.len))
                           << 3};
            size_t pm_len{block_nb << 6};

            std::memset(m_ctx.block + m_ctx.len, 0, pm_len - m_ctx.len);
            m_ctx.block[m_ctx.len] = 0x80;
            UNPACK64(len_b, m_ctx.block + pm_len - 8);

            sha256_transform(m_ctx, m_ctx.block, block_nb);

#if !defined(HASHLIBCXX_USE_LOOPS_UNROLLING)
            for (uint8_t i{0}; i < 7; ++i)
            {
                UNPACK32(m_ctx.h[i], &digest[i << 2]);
            }
#else
            UNPACK32(m_ctx.h[0], &digest[0]);
            UNPACK32(m_ctx.h[1], &digest[4]);
            UNPACK32(m_ctx.h[2], &digest[8]);
            UNPACK32(m_ctx.h[3], &digest[12]);
            UNPACK32(m_ctx.h[4], &digest[16]);
            UNPACK32(m_ctx.h[5], &digest[20]);
            UNPACK32(m_ctx.h[6], &digest[24]);
#endif
        }

    } // namespace sha2
} // namespace hashkitcxx
