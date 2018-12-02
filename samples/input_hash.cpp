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
 * In this example we read text from the standard input, process the hash digest using
 * SHA256 and print the result in the standard output.
 */

#include <hashkitcxx\hash_sha2.hpp>
#include <hashkitcxx\hash_utils.hpp>
#include <iostream>

int main(int /*argc*/, char ** /*argv*/)
{
    using namespace hashkitcxx::sha2;

    std::string content;
    std::cin >> content;

#if defined(HASHLIBCXX_STD_STRING)
    std::string digest{hashkitcxx::hash_printable<sha256>(std::move(content))};
#else
    char digest[sha256::s_digest_size * 2 + 1]{};
    hashkitcxx::hash_printable<sha256>(reinterpret_cast<const unsigned char *>(content.c_str()),
                                       content.size(),
                                       digest);
#endif

    std::cout << digest << std::endl;
}
