/**
 * @file Ed25519.hpp
 * @brief High-performance Ed25519 digital signatures and X25519 key conversion.
 */

#ifndef XI_SEC_ED25519_HPP
#define XI_SEC_ED25519_HPP

#include "X25519.hpp"

namespace Sec {

namespace Ed {

class Keypair;

XI_EXPORT String generateKey();
XI_EXPORT String publicKey(const String &secretKey);

// Ed25519 digital signatures (RFC 8032)
XI_EXPORT String sign(const String &privateKey, const String &message);
XI_EXPORT bool verify(const String &publicKey, const String &message, const String &signature);

// Conversions from Ed25519 to X25519
XI_EXPORT String toXPrivateKey(const String &edSecretKey);
XI_EXPORT String toXPublicKey(const String &edPublicKey);
XI_EXPORT X::Keypair toXKeypair(const Keypair &edKeypair);

class XI_EXPORT PublicKey {
private:
    mutable String _cached;
    const String* _priv = nullptr;
public:
    PublicKey() = default;
    void bind(const String *priv) { _priv = priv; _cached.clear(); }
    void set(const String &pub) { _cached = pub; }
    const String& cached() const { return _cached; }

    const String& get() const;

    operator const String&() const { return get(); }
    operator String() const { return get(); }
    const String& operator()() const { return get(); }

    usz size() const { return get().size(); }
    usz length() const { return get().length(); }
    bool isEmpty() const { return get().isEmpty(); }
    const char* c_str() const { return get().c_str(); }
    const u8* data() const { return get().data(); }
    u8 operator[](usz i) const { return get()[i]; }
    bool operator==(const String &o) const { return get() == o; }
    bool operator!=(const String &o) const { return get() != o; }
    bool operator==(const char *o) const { return get() == o; }
    bool operator!=(const char *o) const { return get() != o; }
};

class XI_EXPORT Keypair {
public:
    String secretKey;
    PublicKey publicKey;

    Keypair();
    Keypair(const String &priv);
    Keypair(const Keypair &o);
    Keypair(Keypair &&o) noexcept;
    Keypair &operator=(const Keypair &o);
    Keypair &operator=(Keypair &&o) noexcept;

    static Keypair generate();
};

// Ed::sharedKey converts keys to X25519 and invokes X::sharedKey
XI_EXPORT String sharedKey(const String &ourEdPrivate, const String &theirEdPublic);
XI_EXPORT String sharedKey(const Keypair &ourEdKeypair, const String &theirEdPublic);

} // namespace Ed

// Convenient top-level alias as requested
inline String sharedKeyEd(const String &ourPrivate, const String &theirPublic) {
    return Ed::sharedKey(ourPrivate, theirPublic);
}

} // namespace Sec

#endif // XI_SEC_ED25519_HPP

