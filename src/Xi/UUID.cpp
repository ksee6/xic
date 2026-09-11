#include "Xi/UUID.hpp"
#include "Xi/Random.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>

namespace Xi {

// Standard Namespaces (RFC 4122)
const UUID UUID::NamespaceDNS  = UUID{0x6ba7b8109dad11d1ULL, 0x80b400c04fd430c8ULL};
const UUID UUID::NamespaceURL  = UUID{0x6ba7b8119dad11d1ULL, 0x80b400c04fd430c8ULL};
const UUID UUID::NamespaceOID  = UUID{0x6ba7b8129dad11d1ULL, 0x80b400c04fd430c8ULL};
const UUID UUID::NamespaceX500 = UUID{0x6ba7b8149dad11d1ULL, 0x80b400c04fd430c8ULL};

// -------------------------------------------------------------------------
// Constructors
// -------------------------------------------------------------------------

UUID::UUID(const String& str) {
    if (!tryParse(str, *this)) {
        hi = 0;
        lo = 0;
    }
}

UUID::UUID(const char* str) {
    if (!str || !tryParse(String(str), *this)) {
        hi = 0;
        lo = 0;
    }
}

UUID::UUID(const u8 bytes[16]) {
    *this = fromBytes(bytes);
}

// -------------------------------------------------------------------------
// Byte Conversions
// -------------------------------------------------------------------------

void UUID::toBytes(u8 bytes[16]) const {
    for (int i = 0; i < 8; i++) {
        bytes[i]     = (u8)((hi >> (56 - i * 8)) & 0xFF);
        bytes[i + 8] = (u8)((lo >> (56 - i * 8)) & 0xFF);
    }
}

UUID UUID::fromBytes(const u8 bytes[16]) {
    UUID u;
    u.hi = 0;
    u.lo = 0;
    for (int i = 0; i < 8; i++) u.hi = (u.hi << 8) | bytes[i];
    for (int i = 8; i < 16; i++) u.lo = (u.lo << 8) | bytes[i];
    return u;
}

// -------------------------------------------------------------------------
// Generation
// -------------------------------------------------------------------------

static u64 getGregorian100ns() {
    auto now = std::chrono::system_clock::now();
    u64 us = (u64)std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    return us * 10ULL + 122192928000000000ULL;
}

UUID UUID::random() {
    UUID u;
    u8 buf[16];
    randomFill(buf, 16);

    u = fromBytes(buf);
    // RFC 4122 v4: version = 4 in hi, variant = 2 (10xx) in lo
    u.hi = (u.hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    u.lo = (u.lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
    return u;
}

UUID UUID::v1() {
    u64 intervals = getGregorian100ns();
    u32 time_low = (u32)intervals;
    u16 time_mid = (u16)(intervals >> 32);
    u16 time_hi = (u16)((intervals >> 48) & 0x0FFF) | 0x1000;

    u8 randBuf[8];
    randomFill(randBuf, 8);
    u16 clock_seq = ((u16)randBuf[0] << 8) | randBuf[1];
    clock_seq = (clock_seq & 0x3FFF) | 0x8000;

    UUID u;
    u.hi = ((u64)time_low << 32) | ((u64)time_mid << 16) | time_hi;
    u.lo = ((u64)clock_seq << 48);
    for (int i = 2; i < 8; i++) u.lo |= ((u64)randBuf[i] << (56 - i * 8));
    return u;
}

UUID UUID::v2(u8 localDomain, u32 localId) {
    u64 intervals = getGregorian100ns();
    u16 time_mid = (u16)(intervals >> 32);
    u16 time_hi = (u16)((intervals >> 48) & 0x0FFF) | 0x2000;

    u8 randBuf[8];
    randomFill(randBuf, 8);
    u16 clock_seq = ((u16)randBuf[0] << 8) | localDomain;
    clock_seq = (clock_seq & 0x3FFF) | 0x8000;

    UUID u;
    u.hi = ((u64)localId << 32) | ((u64)time_mid << 16) | time_hi;
    u.lo = ((u64)clock_seq << 48);
    for (int i = 2; i < 8; i++) u.lo |= ((u64)randBuf[i] << (56 - i * 8));
    return u;
}

UUID UUID::v6() {
    u64 intervals = getGregorian100ns();
    u64 time_high_mid = intervals >> 12;
    u16 time_low_and_version = (u16)(intervals & 0x0FFF) | 0x6000;

    u8 randBuf[8];
    randomFill(randBuf, 8);
    u16 clock_seq = ((u16)randBuf[0] << 8) | randBuf[1];
    clock_seq = (clock_seq & 0x3FFF) | 0x8000;

    UUID u;
    u.hi = (time_high_mid << 16) | time_low_and_version;
    u.lo = ((u64)clock_seq << 48);
    for (int i = 2; i < 8; i++) u.lo |= ((u64)randBuf[i] << (56 - i * 8));
    return u;
}

UUID UUID::v7() {
    auto now = std::chrono::system_clock::now();
    u64 ms = (u64)std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    u8 randBuf[10];
    randomFill(randBuf, 10);

    UUID u;
    u.hi = (ms & 0x0000FFFFFFFFFFFFULL) << 16;
    u.hi |= 0x0000000000007000ULL;
    u16 rand_a = ((u16)randBuf[0] << 8) | randBuf[1];
    u.hi |= (rand_a & 0x0FFF);

    u.lo = 0;
    for (int i = 2; i < 10; i++) u.lo = (u.lo << 8) | randBuf[i];
    u.lo = (u.lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

    return u;
}

UUID UUID::v8(const u8 customData[16]) {
    UUID u = fromBytes(customData);
    u.hi = (u.hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000008000ULL;
    u.lo = (u.lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
    return u;
}

// Self-contained RFC 3174 SHA-1 for RFC 4122 v5 UUID
namespace {
    struct SHA1Ctx {
        u32 state[5];
        u32 count[2];
        u8  buffer[64];

        static inline u32 rol(u32 val, int bits) {
            return (val << bits) | (val >> (32 - bits));
        }

        void transform(const u8 data[64]) {
            u32 a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
            u32 w[80];

            for (int i = 0; i < 16; i++) {
                w[i] = ((u32)data[i * 4] << 24) |
                       ((u32)data[i * 4 + 1] << 16) |
                       ((u32)data[i * 4 + 2] << 8) |
                       ((u32)data[i * 4 + 3]);
            }
            for (int i = 16; i < 80; i++) {
                w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            for (int i = 0; i < 80; i++) {
                u32 f, k;
                if (i < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                u32 temp = rol(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = rol(b, 30);
                b = a;
                a = temp;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
        }

        void init() {
            state[0] = 0x67452301;
            state[1] = 0xEFCDAB89;
            state[2] = 0x98BADCFE;
            state[3] = 0x10325476;
            state[4] = 0xC3D2E1F0;
            count[0] = count[1] = 0;
        }

        void update(const u8* data, usz len) {
            u32 i = 0;
            u32 j = (count[0] >> 3) & 63;
            if ((count[0] += (u32)(len << 3)) < (u32)(len << 3)) count[1]++;
            count[1] += (u32)(len >> 29);
            if ((j + len) > 63) {
                std::memcpy(&buffer[j], data, (i = 64 - j));
                transform(buffer);
                for (; i + 63 < len; i += 64) transform(&data[i]);
                j = 0;
            }
            std::memcpy(&buffer[j], &data[i], len - i);
        }

        void final(u8 digest[20]) {
            u8 finalCount[8];
            for (int i = 0; i < 8; i++) {
                finalCount[i] = (u8)((count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 0xFF);
            }
            update((const u8*)"\200", 1);
            while ((count[0] & 504) != 448) update((const u8*)"\0", 1);
            update(finalCount, 8);
            for (int i = 0; i < 20; i++) {
                digest[i] = (u8)((state[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xFF);
            }
        }
    };

    struct MD5Ctx {
        u32 state[4];
        u32 count[2];
        u8  buffer[64];

        static inline u32 F(u32 x, u32 y, u32 z) { return (x & y) | (~x & z); }
        static inline u32 G(u32 x, u32 y, u32 z) { return (x & z) | (y & ~z); }
        static inline u32 H(u32 x, u32 y, u32 z) { return x ^ y ^ z; }
        static inline u32 I(u32 x, u32 y, u32 z) { return y ^ (x | ~z); }
        static inline u32 rotl(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

        static inline void FF(u32 &a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 ac) {
            a = rotl(a + F(b, c, d) + x + ac, s) + b;
        }
        static inline void GG(u32 &a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 ac) {
            a = rotl(a + G(b, c, d) + x + ac, s) + b;
        }
        static inline void HH(u32 &a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 ac) {
            a = rotl(a + H(b, c, d) + x + ac, s) + b;
        }
        static inline void II(u32 &a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 ac) {
            a = rotl(a + I(b, c, d) + x + ac, s) + b;
        }

        void transform(const u8 block[64]) {
            u32 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
            for (int i = 0; i < 16; i++) {
                x[i] = (u32)block[i*4] | ((u32)block[i*4+1] << 8) |
                       ((u32)block[i*4+2] << 16) | ((u32)block[i*4+3] << 24);
            }
            FF(a, b, c, d, x[ 0], 7, 0xd76aa478); FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
            FF(c, d, a, b, x[ 2], 17, 0x242070db); FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
            FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
            FF(c, d, a, b, x[ 6], 17, 0xa8304613); FF(b, c, d, a, x[ 7], 22, 0xfd469501);
            FF(a, b, c, d, x[ 8], 7, 0x698098d8); FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
            FF(c, d, a, b, x[10], 17, 0xffff5bb1); FF(b, c, d, a, x[11], 22, 0x895cd7be);
            FF(a, b, c, d, x[12], 7, 0x6b901122); FF(d, a, b, c, x[13], 12, 0xfd987193);
            FF(c, d, a, b, x[14], 17, 0xa679438e); FF(b, c, d, a, x[15], 22, 0x49b40821);

            GG(a, b, c, d, x[ 1], 5, 0xf61e2562); GG(d, a, b, c, x[ 6], 9, 0xc040b340);
            GG(c, d, a, b, x[11], 14, 0x265e5a51); GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
            GG(a, b, c, d, x[ 5], 5, 0xd62f105d); GG(d, a, b, c, x[10], 9,  0x2441453);
            GG(c, d, a, b, x[15], 14, 0xd8a1e681); GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
            GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); GG(d, a, b, c, x[14], 9, 0xc33707d6);
            GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
            GG(a, b, c, d, x[13], 5, 0xa9e3e905); GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8);
            GG(c, d, a, b, x[ 7], 14, 0x676f02d9); GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

            HH(a, b, c, d, x[ 5], 4, 0xfffa3942); HH(d, a, b, c, x[ 8], 11, 0x8771f681);
            HH(c, d, a, b, x[11], 16, 0x6d9d6122); HH(b, c, d, a, x[14], 23, 0xfde5380c);
            HH(a, b, c, d, x[ 1], 4, 0xa4beea44); HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
            HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); HH(b, c, d, a, x[10], 23, 0xbebfbc70);
            HH(a, b, c, d, x[13], 4, 0x289b7ec6); HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
            HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); HH(b, c, d, a, x[ 6], 23,  0x4881d05);
            HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); HH(d, a, b, c, x[12], 11, 0xe6db99e5);
            HH(c, d, a, b, x[15], 16, 0x1fa27cf8); HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);

            II(a, b, c, d, x[ 0], 6, 0xf4292244); II(d, a, b, c, x[ 7], 10, 0x432aff97);
            II(c, d, a, b, x[14], 15, 0xab9423a7); II(b, c, d, a, x[ 5], 21, 0xfc93a039);
            II(a, b, c, d, x[12], 6, 0x655b59c3); II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
            II(c, d, a, b, x[10], 15, 0xffeff47d); II(b, c, d, a, x[ 1], 21, 0x85845dd1);
            II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
            II(c, d, a, b, x[ 6], 15, 0xa3014314); II(b, c, d, a, x[13], 21, 0x4e0811a1);
            II(a, b, c, d, x[ 4], 6, 0xf7537e82); II(d, a, b, c, x[11], 10, 0xbd3af235);
            II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); II(b, c, d, a, x[ 9], 21, 0xeb86d391);

            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        }

        void init() {
            count[0] = count[1] = 0;
            state[0] = 0x67452301; state[1] = 0xefcdab89;
            state[2] = 0x98badcfe; state[3] = 0x10325476;
        }

        void update(const u8 *in, usz len) {
            u32 i = 0, idx = (count[0] >> 3) & 63;
            if ((count[0] += ((u32)len << 3)) < ((u32)len << 3)) count[1]++;
            count[1] += ((u32)len >> 29);
            u32 partLen = 64 - idx;
            if (len >= partLen) {
                std::memcpy(&buffer[idx], in, partLen);
                transform(buffer);
                for (i = partLen; i + 63 < len; i += 64) transform(&in[i]);
                idx = 0;
            }
            std::memcpy(&buffer[idx], &in[i], len - i);
        }

        void final(u8 digest[16]) {
            u8 bits[8];
            for (int i = 0; i < 4; i++) {
                bits[i] = (u8)((count[0] >> (i * 8)) & 0xff);
                bits[i + 4] = (u8)((count[1] >> (i * 8)) & 0xff);
            }
            u32 idx = (count[0] >> 3) & 63;
            u32 padLen = (idx < 56) ? (56 - idx) : (120 - idx);
            static const u8 PADDING[64] = { 0x80 };
            update(PADDING, padLen);
            update(bits, 8);
            for (int i = 0; i < 4; i++) {
                digest[i * 4]     = (u8)(state[i] & 0xff);
                digest[i * 4 + 1] = (u8)((state[i] >> 8) & 0xff);
                digest[i * 4 + 2] = (u8)((state[i] >> 16) & 0xff);
                digest[i * 4 + 3] = (u8)((state[i] >> 24) & 0xff);
            }
        }
    };
} // anonymous namespace

UUID UUID::v3(const UUID& ns, const String& name) {
    u8 nsBytes[16];
    ns.toBytes(nsBytes);

    MD5Ctx md5;
    md5.init();
    md5.update(nsBytes, 16);
    md5.update((const u8*)name.c_str(), name.length());

    u8 digest[16];
    md5.final(digest);

    // RFC 4122 v3: version = 3, variant = 2 (10xx)
    digest[6] = (digest[6] & 0x0F) | 0x30;
    digest[8] = (digest[8] & 0x3F) | 0x80;

    return fromBytes(digest);
}

UUID UUID::v5(const UUID& ns, const String& name) {
    u8 nsBytes[16];
    ns.toBytes(nsBytes);

    SHA1Ctx sha1;
    sha1.init();
    sha1.update(nsBytes, 16);
    sha1.update((const u8*)name.c_str(), name.length());

    u8 digest[20];
    sha1.final(digest);

    // RFC 4122 v5: version = 5, variant = 2 (10xx)
    digest[6] = (digest[6] & 0x0F) | 0x50;
    digest[8] = (digest[8] & 0x3F) | 0x80;

    return fromBytes(digest);
}

UUID UUID::fromName(const String& name, const UUID& ns) {
    return v5(ns, name);
}

UUID UUID::fromName(const String& name) {
    return v5(NamespaceDNS, name);
}

// -------------------------------------------------------------------------
// Parsing
// -------------------------------------------------------------------------

static inline int parseHexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool UUID::tryParse(const String& str, UUID& out) {
    String s = str.trim();
    if (s.startsWith("urn:uuid:") || s.startsWith("URN:UUID:")) {
        s = s.substring(9).trim();
    }
    if (s.startsWith("{") && s.endsWith("}")) {
        s = s.substring(1, s.length() - 1).trim();
    }

    u8 bytes[16];
    if (s.length() == 36) {
        // Canonical format: 8-4-4-4-12
        if (s.data()[8] != '-' || s.data()[13] != '-' ||
            s.data()[18] != '-' || s.data()[23] != '-') {
            return false;
        }
        int byteIdx = 0;
        for (usz i = 0; i < 36; i++) {
            if (i == 8 || i == 13 || i == 18 || i == 23) continue;
            int hiNibble = parseHexNibble((char)s.data()[i++]);
            int loNibble = parseHexNibble((char)s.data()[i]);
            if (hiNibble < 0 || loNibble < 0) return false;
            bytes[byteIdx++] = (u8)((hiNibble << 4) | loNibble);
        }
    } else if (s.length() == 32) {
        // Compact hex format: 32 hex chars
        for (int i = 0; i < 16; i++) {
            int hiNibble = parseHexNibble((char)s.data()[i * 2]);
            int loNibble = parseHexNibble((char)s.data()[i * 2 + 1]);
            if (hiNibble < 0 || loNibble < 0) return false;
            bytes[i] = (u8)((hiNibble << 4) | loNibble);
        }
    } else {
        return false;
    }

    out = fromBytes(bytes);
    return true;
}

UUID UUID::fromString(const String& str) {
    UUID out;
    if (tryParse(str, out)) return out;
    return nil();
}

bool UUID::isValid(const String& str) {
    UUID dummy;
    return tryParse(str, dummy);
}

// -------------------------------------------------------------------------
// Formatting
// -------------------------------------------------------------------------

String UUID::toString() const {
    char buf[37];
    snprintf(buf, sizeof(buf),
        "%08x-%04x-%04x-%04x-%012llx",
        (unsigned)(hi >> 32),
        (unsigned)((hi >> 16) & 0xFFFF),
        (unsigned)(hi & 0xFFFF),
        (unsigned)(lo >> 48),
        (unsigned long long)(lo & 0x0000FFFFFFFFFFFFULL));
    return String(buf);
}

String UUID::toCompactString() const {
    char buf[33];
    snprintf(buf, sizeof(buf),
        "%016llx%016llx",
        (unsigned long long)hi,
        (unsigned long long)lo);
    return String(buf);
}

String UUID::toUrn() const {
    return "urn:uuid:" + toString();
}

// -------------------------------------------------------------------------
// Introspection & Hash
// -------------------------------------------------------------------------

u64 UUID::timestamp() const {
    if (version() == 7) {
        return hi >> 16;
    }
    if (version() == 1) {
        u64 time_low = hi >> 32;
        u64 time_mid = (hi >> 16) & 0xFFFF;
        u64 time_hi  = hi & 0x0FFF;
        return (time_hi << 48) | (time_mid << 32) | time_low;
    }
    return 0;
}

usz UUID::hash() const {
    usz h = (usz)(hi ^ (hi >> 32));
    h *= 2654435761ULL;
    h ^= (usz)(lo ^ (lo >> 32));
    h *= 2246822519ULL;
    return h;
}

} // namespace Xi
