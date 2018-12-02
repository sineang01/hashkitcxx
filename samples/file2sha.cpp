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
 * In this example we open a file passed as argument to the executable, read its
 * whole content and build an hash digest from SHA512/256. The hash is then printed
 * in the standard output. Works for any file type.
 */

#include <fstream>
#include <hashkitcxx\hash_sha2.hpp>
#include <iostream>

int main(int argc, char ** argv)
{
    using namespace hashkitcxx::sha2;

    if (argc < 3)
    {
        std::cerr << "error: missing parameter\n"
                  << "usage: file2sha /path/to/file" << std::endl;
        return -1;
    }

    std::string file_name{argv[1]};

    std::ifstream in(file_name, std::ifstream::ate | std::ifstream::binary);
    if (!in.good() || !in.is_open())
    {
        std::cerr << "error: cannot open file" << file_name << std::endl;
        return -1;
    }

    size_t length{static_cast<size_t>(in.tellg())};
    char * file_content = new char[length];
    in.seekg(0, std::ifstream::beg);
    in.read(file_content, static_cast<std::streamsize>(length));

    char digest[sha512_256::s_digest_size * 2 + 1]{};
    sha512_256{}.hash_printable(reinterpret_cast<const unsigned char *>(file_content),
                                length,
                                digest);

    std::cout << digest << std::endl;
    delete[] file_content;
}
