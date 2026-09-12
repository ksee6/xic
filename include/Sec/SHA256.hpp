/**
 * @file SHA256.hpp
 * @brief Standalone SHA-256 implementation for the Xi framework.
 */

#ifndef XI_SEC_SHA256_HPP
#define XI_SEC_SHA256_HPP

#include "../Xi/String.hpp"

namespace Sec {

using namespace Xi;

class XI_EXPORT SHA256 {
public:
    static constexpr usz BlockSize = 64;
    static constexpr usz DigestSize = 32;

    SHA256();
    
    void update(const void* data, usz len);
    void update(const String& str);
    void final(u8 digest[DigestSize]);
    String final();

    static String hash(const String& input);
    static String hash(const void* data, usz len);
    static void hash(const void* data, usz len, u8 digest[DigestSize]);

private:
    u32 state[8];
    u64 count;
    u8 buffer[BlockSize];

    void transform(const u8 block[BlockSize]);

    static const u32 K[64];
};

inline String hashSHA256(const String& input) {
    return SHA256::hash(input);
}

} // namespace Sec

#endif // XI_SEC_SHA256_HPP
