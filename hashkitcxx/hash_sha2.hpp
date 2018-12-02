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

#pragma once
#include <array>
#include <cstdint>
#if defined(HASHLIBCXX_STD_STRING)
#    include <string>
#endif

#if defined(HASHLIBCXX_DLL)
#    undef HASHLIBCXX_DLL
#endif
#if defined(hashlibcxx_library_EXPORTS)
#    define HASHLIBCXX_DLL __declspec(dllexport)
#else
#    define HASHLIBCXX_DLL
#endif

namespace hashkitcxx {
    namespace sha2 {

        // ------------------------------------------------------------------
        // --- sha-224 ------------------------------------------------------

        class HASHLIBCXX_DLL sha224 final
        {
          private:
            static constexpr size_t s_block_size{
                512 / 8}; /**< Size expressed in byte of the block handled in the iterations */

          public:
            static constexpr size_t s_digest_size{
                224 / 8}; /**< Size expressed in byte of the resulting hash */

            struct ctx_t
            {
                size_t tot_len{0};
                size_t len{0};
                unsigned char block[2 * s_block_size]{};
                uint32_t h[8]{};
            };

          public:
            sha224() = default;
            ~sha224() {}
            sha224(sha224 &&) = default;
            sha224(const sha224 &) = default;
            sha224 & operator=(sha224 &&) = default;
            sha224 & operator=(const sha224 &) = default;

#if defined(HASHLIBCXX_STD_STRING)
            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(std::string && message)
            {
                return hash_printable(reinterpret_cast<const unsigned char *>(message.c_str()),
                                      message.size());
            }

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(const unsigned char * message, size_t len)
            {
                char digest_printable[2 * s_digest_size + 1]{};
                hash_printable(message, len, digest_printable);
                return std::string(digest_printable);
            }

            /**
             * @brief Returns the hash of the given input.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(std::string && message, unsigned char * digest)
            {
                hash(reinterpret_cast<const unsigned char *>(message.c_str()),
                     message.size(),
                     digest);
            }
#endif

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest_printable pointer to the memory location to store the hash of `message`
             * in hex.
             */
            void hash_printable(const unsigned char * message,
                                size_t len,
                                char * digest_printable) noexcept;

            /**
             * @brief Returns the hash of the given input.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(const unsigned char * message,
                             size_t len,
                             unsigned char * digest) noexcept
            {
                init();
                update(message, len);
                complete(digest);
            }

          private:
            void init() noexcept;
            void update(const unsigned char * message, size_t len) noexcept;
            void complete(unsigned char * digest) noexcept;

          private:
            ctx_t m_ctx; /**< Stores temporary data while the hash is being computed */
        };

        // ------------------------------------------------------------------
        // --- sha-256 ------------------------------------------------------

        class HASHLIBCXX_DLL sha256 final
        {
          private:
            static constexpr size_t s_block_size{
                512 / 8}; /**< Size expressed in byte of the block handled in the iterations */

          public:
            static constexpr size_t s_digest_size{
                256 / 8}; /**< Size expressed in byte of the resulting hash */

            struct ctx_t
            {
                size_t tot_len{0};
                size_t len{0};
                unsigned char block[2 * s_block_size]{};
                uint32_t h[8]{};
            };

          public:
            sha256() = default;
            ~sha256() {}
            sha256(sha256 &&) = default;
            sha256(const sha256 &) = default;
            sha256 & operator=(sha256 &&) = default;
            sha256 & operator=(const sha256 &) = default;

#if defined(HASHLIBCXX_STD_STRING)
            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(std::string && message)
            {
                return hash_printable(reinterpret_cast<const unsigned char *>(message.c_str()),
                                      message.size());
            }

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(const unsigned char * message, size_t len)
            {
                char digest_printable[2 * s_digest_size + 1]{};
                hash_printable(message, len, digest_printable);
                return std::string(digest_printable);
            }

            /**
             * @brief Returns the hash of the given input.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(std::string && message, unsigned char * digest)
            {
                hash(reinterpret_cast<const unsigned char *>(message.c_str()),
                     message.size(),
                     digest);
            }
#endif

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest_printable pointer to the memory location to store the hash of `message`
             * in hex.
             */
            void hash_printable(const unsigned char * message,
                                size_t len,
                                char * digest_printable) noexcept;

            /**
             * @brief Returns the hash of the given input.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(const unsigned char * message,
                             size_t len,
                             unsigned char * digest) noexcept
            {
                init();
                update(message, len);
                complete(digest);
            }

          private:
            void init() noexcept;
            void update(const unsigned char * message, size_t len) noexcept;
            void complete(unsigned char * digest) noexcept;

          private:
            ctx_t m_ctx; /**< Stores temporary data while the hash is being computed */
        };

        // ------------------------------------------------------------------
        // --- sha-384 ------------------------------------------------------

        class HASHLIBCXX_DLL sha384 final
        {
          private:
            static constexpr size_t s_block_size{
                1024 / 8}; /**< Size expressed in byte of the block handled in the iterations */

          public:
            static constexpr size_t s_digest_size{
                384 / 8}; /**< Size expressed in byte of the resulting hash */

            struct ctx_t
            {
                size_t tot_len{0};
                size_t len{0};
                unsigned char block[2 * s_block_size]{};
                uint64_t h[8]{};
            };

          public:
            sha384() = default;
            ~sha384() {}
            sha384(sha384 &&) = default;
            sha384(const sha384 &) = default;
            sha384 & operator=(sha384 &&) = default;
            sha384 & operator=(const sha384 &) = default;

#if defined(HASHLIBCXX_STD_STRING)
            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(std::string && message)
            {
                return hash_printable(reinterpret_cast<const unsigned char *>(message.c_str()),
                                      message.size());
            }

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(const unsigned char * message, size_t len)
            {
                char digest_printable[2 * s_digest_size + 1]{};
                hash_printable(message, len, digest_printable);
                return std::string(digest_printable);
            }

            /**
             * @brief Returns the hash of the given input.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(std::string && message, unsigned char * digest)
            {
                hash(reinterpret_cast<const unsigned char *>(message.c_str()),
                     message.size(),
                     digest);
            }
#endif

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest_printable pointer to the memory location to store the hash of `message`
             * in hex.
             */
            void hash_printable(const unsigned char * message,
                                size_t len,
                                char * digest_printable) noexcept;

            /**
             * @brief Returns the hash of the given input.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(const unsigned char * message,
                             size_t len,
                             unsigned char * digest) noexcept
            {
                init();
                update(message, len);
                complete(digest);
            }

          private:
            void init() noexcept;
            void update(const unsigned char * message, size_t len) noexcept;
            void complete(unsigned char * digest) noexcept;

          private:
            ctx_t m_ctx; /**< Stores temporary data while the hash is being computed */
        };

        // ------------------------------------------------------------------
        // --- sha-512 ------------------------------------------------------

        class HASHLIBCXX_DLL sha512 final
        {
          private:
            static constexpr size_t s_block_size{
                1024 / 8}; /**< Size expressed in byte of the block handled in the iterations */

          public:
            static constexpr size_t s_digest_size{
                512 / 8}; /**< Size expressed in byte of the resulting hash */

            struct ctx_t
            {
                size_t tot_len{0};
                size_t len{0};
                unsigned char block[2 * s_block_size]{};
                uint64_t h[8]{};
            };

          public:
            sha512();
            sha512(const std::array<uint64_t, 8> & h0);
            ~sha512() {}
            sha512(sha512 &&) = default;
            sha512(const sha512 &) = default;
            sha512 & operator=(sha512 &&) = default;
            sha512 & operator=(const sha512 &) = default;

#if defined(HASHLIBCXX_STD_STRING)
            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(std::string && message)
            {
                return hash_printable(reinterpret_cast<const unsigned char *>(message.c_str()),
                                      message.size());
            }

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(const unsigned char * message, size_t len)
            {
                char digest_printable[2 * s_digest_size + 1]{};
                hash_printable(message, len, digest_printable);
                return std::string(digest_printable);
            }

            /**
             * @brief Returns the hash of the given input.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(std::string && message, unsigned char * digest)
            {
                hash(reinterpret_cast<const unsigned char *>(message.c_str()),
                     message.size(),
                     digest);
            }
#endif

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest_printable pointer to the memory location to store the hash of `message`
             * in hex.
             */
            void hash_printable(const unsigned char * message,
                                size_t len,
                                char * digest_printable) noexcept;

            /**
             * @brief Returns the hash of the given input.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(const unsigned char * message,
                             size_t len,
                             unsigned char * digest) noexcept
            {
                init();
                update(message, len);
                complete(digest);
            }

          private:
            void init() noexcept;
            void update(const unsigned char * message, size_t len) noexcept;
            void complete(unsigned char * digest) noexcept;

          private:
            ctx_t m_ctx; /**< Stores temporary data while the hash is being computed */
            std::array<uint64_t, 8> m_h0; /* Stores the initial hash value h0 */
        };

        // ------------------------------------------------------------------
        // --- sha-512/224 --------------------------------------------------

        class HASHLIBCXX_DLL sha512_224 final
        {
          public:
            static constexpr size_t s_digest_size{
                224 / 8}; /**< Size expressed in byte of the resulting hash */

          public:
            sha512_224() = default;
            ~sha512_224() {}
            sha512_224(sha512_224 &&) = default;
            sha512_224(const sha512_224 &) = default;
            sha512_224 & operator=(sha512_224 &&) = default;
            sha512_224 & operator=(const sha512_224 &) = default;

#if defined(HASHLIBCXX_STD_STRING)
            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(std::string && message)
            {
                return hash_printable(reinterpret_cast<const unsigned char *>(message.c_str()),
                                      message.size());
            }

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(const unsigned char * message, size_t len)
            {
                char digest_printable[2 * s_digest_size + 1]{};
                hash_printable(message, len, digest_printable);
                return std::string(digest_printable);
            }

            /**
             * @brief Returns the hash of the given input.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(std::string && message, unsigned char * digest)
            {
                hash(reinterpret_cast<const unsigned char *>(message.c_str()),
                     message.size(),
                     digest);
            }
#endif

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest_printable pointer to the memory location to store the hash of `message`
             * in hex.
             */
            void hash_printable(const unsigned char * message,
                                size_t len,
                                char * digest_printable) noexcept;

            /**
             * @brief Returns the hash of the given input.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            void hash(const unsigned char * message, size_t len, unsigned char * digest) noexcept;
        };

        // ------------------------------------------------------------------
        // --- sha-512/256 --------------------------------------------------

        class HASHLIBCXX_DLL sha512_256 final
        {
          public:
            static constexpr size_t s_digest_size{
                256 / 8}; /**< Size expressed in byte of the resulting hash */

          public:
            sha512_256() = default;
            ~sha512_256() {}
            sha512_256(sha512_256 &&) = default;
            sha512_256(const sha512_256 &) = default;
            sha512_256 & operator=(sha512_256 &&) = default;
            sha512_256 & operator=(const sha512_256 &) = default;

#if defined(HASHLIBCXX_STD_STRING)
            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(std::string && message)
            {
                return hash_printable(reinterpret_cast<const unsigned char *>(message.c_str()),
                                      message.size());
            }

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @return a string containing the hash of `message` in hex.
             */
            inline std::string hash_printable(const unsigned char * message, size_t len)
            {
                char digest_printable[2 * s_digest_size + 1]{};
                hash_printable(message, len, digest_printable);
                return std::string(digest_printable);
            }

            /**
             * @brief Returns the hash of the given input.
             * @param message the text to hash. This function takes a string in input so the message
             * cannot contain \0 characters in the middle.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            inline void hash(std::string && message, unsigned char * digest)
            {
                hash(reinterpret_cast<const unsigned char *>(message.c_str()),
                     message.size(),
                     digest);
            }
#endif

            /**
             * @brief Returns the hash of the given input in hex format.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest_printable pointer to the memory location to store the hash of `message`
             * in hex.
             */
            void hash_printable(const unsigned char * message,
                                size_t len,
                                char * digest_printable) noexcept;

            /**
             * @brief Returns the hash of the given input.
             * @param message pointer to the memory location containing the byte-array to hash.
             * @param len the total length of `message` expressed in bytes.
             * @param digest pointer to the memory location to store the hash of `message`.
             */
            void hash(const unsigned char * message, size_t len, unsigned char * digest) noexcept;
        };

    } // namespace sha2
} // namespace hashkitcxx
