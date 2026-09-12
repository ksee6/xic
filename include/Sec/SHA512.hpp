/**
 * @file SHA512.hpp
 * @brief Standalone high-performance SHA-512 implementation for the Xi framework.
 */

#ifndef XI_SEC_SHA512_HPP
#define XI_SEC_SHA512_HPP

#include "../Xi/String.hpp"

namespace Sec {

using namespace Xi;

class XI_EXPORT SHA512 {
public:
    static constexpr usz BlockSize = 128;
    static constexpr usz DigestSize = 64;

    SHA512();

    void init();
    void update(const void* data, usz len);
    void update(const String& str);
    void final(u8 digest[DigestSize]);
    String final();

    static String hash(const String& input);
    static String hash(const void* data, usz len);
    static void hash(const void* data, usz len, u8 digest[DigestSize]);

private:
    u64 state[8];
    u64 count[2]; // total bits: count[0] = low 64, count[1] = high 64
    u8 buffer[BlockSize];

    void transform(const u8 block[BlockSize]);

    static const u64 K[80];
};

inline String hashSHA512(const String& input) {
    return SHA512::hash(input);
}

} // namespace Sec

#endif // XI_SEC_SHA512_HPP

