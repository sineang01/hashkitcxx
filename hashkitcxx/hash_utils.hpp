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
 */

#pragma once
#include <utility>
#if defined(HASHLIBCXX_STD_STRING)
#    include <string>
#endif

namespace hashkitcxx {

#if defined(HASHLIBCXX_STD_STRING)
    /**
     * @brief Returns the hash of the given input in hex format.
     * @tparam THash a default constructible object containing an accessible function
     * `hash_printable` with the same signature of this one.
     * @param message the text to hash. This function takes a string in input so the message cannot
     * contain \0 characters in the middle.
     * @return a string containing the hash of `message` in hex.
     */
    template<class THash>
    std::string hash_printable(std::string && message)
    {
        THash s;
        return s.hash_printable(std::forward<std::string>(message));
    }

    /**
     * @brief Returns the hash of the given input in hex format.
     * @tparam THash a default constructible object containing an accessible function
     * `hash_printable` with the same signature of this one.
     * @param message pointer to the memory location containing the byte-array to hash.
     * @param len the total length of `message` expressed in bytes.
     * @return a string containing the hash of `message` in hex.
     */
    template<class THash>
    std::string hash_printable(const unsigned char * message, size_t len)
    {
        THash s;
        return s.hash_printable(message, len);
    }

    /**
     * @brief Returns the hash of the given input.
     * @tparam THash a default constructible object containing an accessible function `hash` with
     * the same signature of this one.
     * @param message the text to hash. This function takes a string in input so the message cannot
     * contain \0 characters in the middle.
     * @param digest pointer to the memory location to store the hash of `message`.
     */
    template<class THash>
    void hash(std::string && message, unsigned char * digest)
    {
        THash s;
        s.hash(std::forward<std::string>(message), digest);
    }
#endif

    /**
     * @brief Returns the hash of the given input in hex format.
     * @tparam THash a default constructible object containing an accessible function
     * `hash_printable` with the same signature of this one.
     * @param message pointer to the memory location containing the byte-array to hash.
     * @param len the total length of `message` expressed in bytes.
     * @param digest_printable pointer to the memory location to store the hash of `message` in hex.
     */
    template<class THash>
    void hash_printable(const unsigned char * message, size_t len, char * digest_printable) noexcept
    {
        THash s;
        s.hash_printable(message, len, digest_printable);
    }

    /**
     * @brief Returns the hash of the given input.
     * @tparam THash a default constructible object containing an accessible function `hash` with
     * the same signature of this one.
     * @param message pointer to the memory location containing the byte-array to hash.
     * @param len the total length of `message` expressed in bytes.
     * @param digest pointer to the memory location to store the hash of `message`.
     */
    template<class THash>
    void hash(const unsigned char * message, size_t len, unsigned char * digest) noexcept
    {
        THash s;
        s.hash(message, len, digest);
    }

} // namespace hashkitcxx
