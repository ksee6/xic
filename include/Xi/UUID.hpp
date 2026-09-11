/**
 * @file UUID.hpp
 * @brief 128-bit Universally Unique Identifier (RFC 4122 / RFC 9562).
 */

#ifndef XI_UUID_HPP
#define XI_UUID_HPP

#include "Xi.hpp"
#include "String.hpp"

namespace Xi {

struct XI_EXPORT UUID {
    u64 hi = 0;
    u64 lo = 0;

    // ---- Standard Constants ----
    static constexpr UUID nil() { return UUID{0, 0}; }
    static constexpr UUID max() { return UUID{~0ULL, ~0ULL}; }

    static const UUID NamespaceDNS;
    static const UUID NamespaceURL;
    static const UUID NamespaceOID;
    static const UUID NamespaceX500;

    // ---- Constructors ----
    constexpr UUID() = default;
    constexpr UUID(u64 hi, u64 lo) : hi(hi), lo(lo) {}
    UUID(const String& str);
    UUID(const char* str);
    explicit UUID(const u8 bytes[16]);

    // ---- Generation (all versions: v1 through v8) ----
    static UUID random();
    static UUID v1();
    static UUID v2(u8 localDomain = 0, u32 localId = 0);
    static UUID v3(const UUID& ns, const String& name);
    static UUID v4() { return random(); }
    static UUID v5(const UUID& ns, const String& name);
    static UUID v6();
    static UUID v7();
    static UUID v8(const u8 customData[16]);
    static UUID fromName(const String& name, const UUID& ns);
    static UUID fromName(const String& name);

    // ---- Parsing ----
    static UUID fromString(const String& str);
    static bool tryParse(const String& str, UUID& out);
    static bool isValid(const String& str);

    // ---- Formatting ----
    String toString() const;
    String toCompactString() const;
    String toUrn() const;

    // ---- Byte Conversions ----
    void toBytes(u8 bytes[16]) const;
    static UUID fromBytes(const u8 bytes[16]);

    // ---- Introspection ----
    bool isNil() const { return hi == 0 && lo == 0; }
    bool isMax() const { return hi == ~0ULL && lo == ~0ULL; }
    u8   version() const { return (u8)((hi >> 12) & 0x0F); }
    u8   variant() const { return (u8)((lo >> 62) & 0x03); }
    u64  timestamp() const;

    // ---- Comparison & Hash ----
    bool operator==(const UUID& o) const { return hi == o.hi && lo == o.lo; }
    bool operator!=(const UUID& o) const { return !(*this == o); }
    bool operator< (const UUID& o) const {
        if (hi != o.hi) return hi < o.hi;
        return lo < o.lo;
    }
    bool operator<=(const UUID& o) const { return *this < o || *this == o; }
    bool operator> (const UUID& o) const { return !(*this <= o); }
    bool operator>=(const UUID& o) const { return !(*this < o); }

    bool operator!() const { return isNil(); }
    explicit operator bool() const { return !isNil(); }

    usz hash() const;
};

} // namespace Xi

#endif // XI_UUID_HPP
