#pragma once
#include <cassert>
#include <cstdio>

namespace common {

    inline void to_hex(const unsigned char * digest, size_t digest_size, char * out)
    {
        assert(digest);
        assert(out);

        for (size_t i{0}; i < digest_size; ++i)
            sprintf(out + i * 2, "%02x", digest[i]);
    }

} // namespace common
