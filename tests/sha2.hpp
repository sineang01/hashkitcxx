#pragma once
#define BOOST_TEST_DYN_LINK
#include "common.hpp"
#include <boost/test/unit_test.hpp>
#include <hashkitcxx/hash_sha2.hpp>
#include <hashkitcxx/hash_utils.hpp>

static constexpr bool enable_test_1GB{true};

BOOST_AUTO_TEST_SUITE(test_sha2)
struct fixture_test_string_1GB
{
    fixture_test_string_1GB()
    {
        static constexpr size_t repeats{16777216};
        const char * message_unit =
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
        const size_t message_unit_size{strlen(message_unit)};
        message_size = repeats * message_unit_size;
        message = new unsigned char[message_size];
        memset(message, 0, message_size);

        {
            unsigned char * origin = message;
            for (size_t i{0}; i < repeats; ++i)
            {
                memcpy(origin, message_unit, message_unit_size);
                origin += message_unit_size;
            }
        }
    }

    ~fixture_test_string_1GB() { delete message; }

    unsigned char * message;
    size_t message_size;
};

BOOST_AUTO_TEST_SUITE(test_sha224)
BOOST_AUTO_TEST_CASE(test_abc)
{
    const char * message{"abc"};
    const size_t message_size{3};
    unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha224>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output);
}
BOOST_AUTO_TEST_CASE(test_empty)
{
    const char * message = "";
    const size_t message_size{0};

    unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha224>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" == output);
}
BOOST_AUTO_TEST_CASE(test_string_448bits)
{
    const char * message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const size_t message_size{56};

    unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha224>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" == output);
}
BOOST_AUTO_TEST_CASE(test_string_896bits)
{
    const char * message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmno"
                           "pjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const size_t message_size{112};

    unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha224>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3" == output);
}
BOOST_AUTO_TEST_CASE(test_string_one_million_times)
{
    static constexpr size_t message_size{1000000};
    unsigned char message[message_size];
    memset(message, 'a', message_size);

    unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha224>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67" == output);
}
BOOST_FIXTURE_TEST_CASE(test_string_1GB,
                        fixture_test_string_1GB,
                        *boost::unit_test_framework::enable_if<enable_test_1GB>())
{
    unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha224>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85" == output);
}
BOOST_AUTO_TEST_CASE(test_hash_overloads)
{
    {
        hashkitcxx::sha2::sha224 h;
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
        h.hash(reinterpret_cast<const unsigned char *>(message), message_size, digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha224>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha224 h;
        unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
        h.hash("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output);
    }

    {
        unsigned char digest[hashkitcxx::sha2::sha224::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha224>("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output);
    }
#endif
}
BOOST_AUTO_TEST_CASE(test_hash_printable_overloads)
{
    {
        hashkitcxx::sha2::sha224 h;
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha224::s_digest_size * 2 + 1];
        h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha224::s_digest_size * 2 + 1];
        hashkitcxx::hash_printable<hashkitcxx::sha2::sha224>(
            reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha224 h;
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{
            h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output.c_str());
    }

    {
        hashkitcxx::sha2::sha224 h;
        std::string output{h.hash_printable("abc")};

        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output.c_str());
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha224>(
            reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output.c_str());
    }

    {
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha224>("abc")};

        BOOST_TEST("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == output.c_str());
    }
#endif
}
BOOST_AUTO_TEST_SUITE_END() // test_sha224

BOOST_AUTO_TEST_SUITE(test_sha256)
BOOST_AUTO_TEST_CASE(test_abc)
{
    const char * message{"abc"};
    const size_t message_size{3};

    unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha256>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" == output);
}
BOOST_AUTO_TEST_CASE(test_empty)
{
    const char * message = "";
    const size_t message_size{0};

    unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha256>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" == output);
}
BOOST_AUTO_TEST_CASE(test_string_448bits)
{
    const char * message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const size_t message_size{56};

    unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha256>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" == output);
}
BOOST_AUTO_TEST_CASE(test_string_896bits)
{
    const char * message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmno"
                           "pjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const size_t message_size{112};

    unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha256>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" == output);
}
BOOST_AUTO_TEST_CASE(test_string_one_million_times)
{
    static constexpr size_t message_size{1000000};
    unsigned char message[message_size];
    memset(message, 'a', message_size);

    unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha256>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" == output);
}
BOOST_FIXTURE_TEST_CASE(test_string_1GB,
                        fixture_test_string_1GB,
                        *boost::unit_test_framework::enable_if<enable_test_1GB>())
{
    unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha256>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e" == output);
}
BOOST_AUTO_TEST_CASE(test_hash_overloads)
{
    {
        hashkitcxx::sha2::sha256 h;
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
        h.hash(reinterpret_cast<const unsigned char *>(message), message_size, digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha256>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha256 h;
        unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
        h.hash("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" == output);
    }

    {
        unsigned char digest[hashkitcxx::sha2::sha256::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha256>("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" == output);
    }
#endif
}
BOOST_AUTO_TEST_CASE(test_hash_printable_overloads)
{
    {
        hashkitcxx::sha2::sha256 h;
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha256::s_digest_size * 2 + 1];
        h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha256::s_digest_size * 2 + 1];
        hashkitcxx::hash_printable<hashkitcxx::sha2::sha256>(
            reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha256 h;
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{
            h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ==
                   output.c_str());
    }

    {
        hashkitcxx::sha2::sha256 h;
        std::string output{h.hash_printable("abc")};

        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ==
                   output.c_str());
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha256>(
            reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ==
                   output.c_str());
    }

    {
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha256>("abc")};

        BOOST_TEST("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ==
                   output.c_str());
    }
#endif
}
BOOST_AUTO_TEST_SUITE_END() // test_sha256

BOOST_AUTO_TEST_SUITE(test_sha384)
BOOST_AUTO_TEST_CASE(test_abc)
{
    const char * message{"abc"};
    const size_t message_size{3};

    unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha384>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358b"
               "aeca134c825a7" == output);
}
BOOST_AUTO_TEST_CASE(test_empty)
{
    const char * message = "";
    const size_t message_size{0};

    unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha384>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51"
               "ad2f14898b95b" == output);
}
BOOST_AUTO_TEST_CASE(test_string_448bits)
{
    const char * message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const size_t message_size{56};

    unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha384>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe"
               "95b1fe3c8452b" == output);
}
BOOST_AUTO_TEST_CASE(test_string_896bits)
{
    const char * message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmno"
                           "pjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const size_t message_size{112};

    unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha384>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c"
               "3e9fa91746039" == output);
}
BOOST_AUTO_TEST_CASE(test_string_one_million_times)
{
    static constexpr size_t message_size{1000000};
    unsigned char message[message_size];
    memset(message, 'a', message_size);

    unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha384>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae9"
               "7ddd87f3d8985" == output);
}
BOOST_FIXTURE_TEST_CASE(test_string_1GB,
                        fixture_test_string_1GB,
                        *boost::unit_test_framework::enable_if<enable_test_1GB>())
{
    unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha384>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04"
               "f11b31b89f023" == output);
}
BOOST_AUTO_TEST_CASE(test_overloads)
{
    {
        hashkitcxx::sha2::sha384 h;
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
        h.hash(reinterpret_cast<const unsigned char *>(message), message_size, digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha384>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha384 h;
        unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
        h.hash("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output);
    }

    {
        unsigned char digest[hashkitcxx::sha2::sha384::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha384>("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output);
    }
#endif
}
BOOST_AUTO_TEST_CASE(test_printable_overloads)
{
    {
        hashkitcxx::sha2::sha384 h;
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha384::s_digest_size * 2 + 1];
        h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha384::s_digest_size * 2 + 1];
        hashkitcxx::hash_printable<hashkitcxx::sha2::sha384>(
            reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha384 h;
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{
            h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output.c_str());
    }

    {
        hashkitcxx::sha2::sha384 h;
        std::string output{h.hash_printable("abc")};

        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output.c_str());
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha384>(
            reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output.c_str());
    }

    {
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha384>("abc")};

        BOOST_TEST("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2"
                   "358baeca134c825a7" == output.c_str());
    }
#endif
}
BOOST_AUTO_TEST_SUITE_END() // test_sha384

BOOST_AUTO_TEST_SUITE(test_sha512)
BOOST_AUTO_TEST_CASE(test_abc)
{
    const char * message{"abc"};
    const size_t message_size{3};

    unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836b"
               "a3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output);
}
BOOST_AUTO_TEST_CASE(test_empty)
{
    const char * message = "";
    const size_t message_size{0};

    unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8"
               "318d2877eec2f63b931bd47417a81a538327af927da3e" == output);
}
BOOST_AUTO_TEST_CASE(test_string_448bits)
{
    const char * message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const size_t message_size{56};

    unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1"
               "d3bea57789ca031ad85c7a71dd70354ec631238ca3445" == output);
}
BOOST_AUTO_TEST_CASE(test_string_896bits)
{
    const char * message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmno"
                           "pjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const size_t message_size{112};

    unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331"
               "b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" == output);
}
BOOST_AUTO_TEST_CASE(test_string_one_million_times)
{
    static constexpr size_t message_size{1000000};
    unsigned char message[message_size];
    memset(message, 'a', message_size);

    unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb"
               "0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b" == output);
}
BOOST_FIXTURE_TEST_CASE(test_string_1GB,
                        fixture_test_string_1GB,
                        *boost::unit_test_framework::enable_if<enable_test_1GB>())
{
    unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512>(reinterpret_cast<const unsigned char *>(message),
                                               message_size,
                                               digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2"
               "967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086" == output);
}
BOOST_AUTO_TEST_CASE(test_overloads)
{
    {
        hashkitcxx::sha2::sha512 h;
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
        h.hash(reinterpret_cast<const unsigned char *>(message), message_size, digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha512>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha512 h;
        unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
        h.hash("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output);
    }

    {
        unsigned char digest[hashkitcxx::sha2::sha512::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha512>("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output);
    }
#endif
}
BOOST_AUTO_TEST_CASE(test_printable_overloads)
{
    {
        hashkitcxx::sha2::sha512 h;
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha512::s_digest_size * 2 + 1];
        h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha512::s_digest_size * 2 + 1];
        hashkitcxx::hash_printable<hashkitcxx::sha2::sha512>(
            reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha512 h;
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{
            h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output.c_str());
    }

    {
        hashkitcxx::sha2::sha512 h;
        std::string output{h.hash_printable("abc")};

        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output.c_str());
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha512>(
            reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output.c_str());
    }

    {
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha512>("abc")};

        BOOST_TEST("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a"
                   "836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == output.c_str());
    }
#endif
}
BOOST_AUTO_TEST_SUITE_END() // test_sha512

BOOST_AUTO_TEST_SUITE(test_sha512_224)
BOOST_AUTO_TEST_CASE(test_abc)
{
    const char * message{"abc"};
    const size_t message_size{3};

    unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_224>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output);
}
BOOST_AUTO_TEST_CASE(test_empty)
{
    const char * message = "";
    const size_t message_size{0};

    unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_224>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" == output);
}
BOOST_AUTO_TEST_CASE(test_string_448bits)
{
    const char * message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const size_t message_size{56};

    unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_224>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174" == output);
}
BOOST_AUTO_TEST_CASE(test_string_896bits)
{
    const char * message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmno"
                           "pjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const size_t message_size{112};

    unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_224>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9" == output);
}
BOOST_AUTO_TEST_CASE(test_string_one_million_times)
{
    static constexpr size_t message_size{1000000};
    unsigned char message[message_size];
    memset(message, 'a', message_size);

    unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_224>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287" == output);
}
BOOST_FIXTURE_TEST_CASE(test_string_1GB,
                        fixture_test_string_1GB,
                        *boost::unit_test_framework::enable_if<enable_test_1GB>())
{
    unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_224>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("9a7f86727c3be1403d6702617646b15589b8c5a92c70f1703cd25b52" == output);
}
BOOST_AUTO_TEST_CASE(test_overloads)
{
    {
        hashkitcxx::sha2::sha512_224 h;
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
        h.hash(reinterpret_cast<const unsigned char *>(message), message_size, digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha512_224>(reinterpret_cast<const unsigned char *>(
                                                           message),
                                                       message_size,
                                                       digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha512_224 h;
        unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
        h.hash("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output);
    }

    {
        unsigned char digest[hashkitcxx::sha2::sha512_224::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha512_224>("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output);
    }
#endif
}
BOOST_AUTO_TEST_CASE(test_printable_overloads)
{
    {
        hashkitcxx::sha2::sha512_224 h;
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha512_224::s_digest_size * 2 + 1];
        h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha512_224::s_digest_size * 2 + 1];
        hashkitcxx::hash_printable<hashkitcxx::sha2::sha512_224>(
            reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha512_224 h;
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{
            h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output.c_str());
    }

    {
        hashkitcxx::sha2::sha512_224 h;
        std::string output{h.hash_printable("abc")};

        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output.c_str());
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha512_224>(
            reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output.c_str());
    }

    {
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha512_224>("abc")};

        BOOST_TEST("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" == output.c_str());
    }
#endif
}
BOOST_AUTO_TEST_SUITE_END() // test_sha512_224

BOOST_AUTO_TEST_SUITE(test_sha512_256)
BOOST_AUTO_TEST_CASE(test_abc)
{
    const char * message{"abc"};
    const size_t message_size{3};

    unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_256>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" == output);
}
BOOST_AUTO_TEST_CASE(test_empty)
{
    const char * message = "";
    const size_t message_size{0};

    unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_256>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" == output);
}
BOOST_AUTO_TEST_CASE(test_string_448bits)
{
    const char * message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const size_t message_size{56};

    unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_256>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461" == output);
}
BOOST_AUTO_TEST_CASE(test_string_896bits)
{
    const char * message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmno"
                           "pjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const size_t message_size{112};

    unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_256>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a" == output);
}
BOOST_AUTO_TEST_CASE(test_string_one_million_times)
{
    static constexpr size_t message_size{1000000};
    unsigned char message[message_size];
    memset(message, 'a', message_size);

    unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_256>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21" == output);
}
BOOST_FIXTURE_TEST_CASE(test_string_1GB,
                        fixture_test_string_1GB,
                        *boost::unit_test_framework::enable_if<enable_test_1GB>())
{
    unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
    hashkitcxx::hash<hashkitcxx::sha2::sha512_256>(reinterpret_cast<const unsigned char *>(message),
                                                   message_size,
                                                   digest);

    char output[2 * sizeof(digest) + 1]{};
    common::to_hex(digest, sizeof(digest), output);
    BOOST_TEST("b5855a6179802ce567cbf43888284c6ac7c3f6c48b08c5bc1e8ad75d12782c9e" == output);
}
BOOST_AUTO_TEST_CASE(test_overloads)
{
    {
        hashkitcxx::sha2::sha512_256 h;
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
        h.hash(reinterpret_cast<const unsigned char *>(message), message_size, digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha512_256>(reinterpret_cast<const unsigned char *>(
                                                           message),
                                                       message_size,
                                                       digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha512_256 h;
        unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
        h.hash("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" == output);
    }

    {
        unsigned char digest[hashkitcxx::sha2::sha512_256::s_digest_size];
        hashkitcxx::hash<hashkitcxx::sha2::sha512_256>("abc", digest);

        char output[2 * sizeof(digest) + 1]{};
        common::to_hex(digest, sizeof(digest), output);
        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" == output);
    }
#endif
}
BOOST_AUTO_TEST_CASE(test_printable_overloads)
{
    {
        hashkitcxx::sha2::sha512_256 h;
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha512_256::s_digest_size * 2 + 1];
        h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" == output);
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        char output[hashkitcxx::sha2::sha512_256::s_digest_size * 2 + 1];
        hashkitcxx::hash_printable<hashkitcxx::sha2::sha512_256>(
            reinterpret_cast<const unsigned char *>(message), message_size, output);

        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" == output);
    }

#if defined(HASHLIBCXX_STD_STRING)
    {
        hashkitcxx::sha2::sha512_256 h;
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{
            h.hash_printable(reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" ==
                   output.c_str());
    }

    {
        hashkitcxx::sha2::sha512_256 h;
        std::string output{h.hash_printable("abc")};

        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" ==
                   output.c_str());
    }

    {
        const char * message{"abc"};
        const size_t message_size{3};
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha512_256>(
            reinterpret_cast<const unsigned char *>(message), message_size)};

        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" ==
                   output.c_str());
    }

    {
        std::string output{hashkitcxx::hash_printable<hashkitcxx::sha2::sha512_256>("abc")};

        BOOST_TEST("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" ==
                   output.c_str());
    }
#endif
}
BOOST_AUTO_TEST_SUITE_END() // test_sha512_256

BOOST_AUTO_TEST_SUITE_END() // test_sha2
