/**
 * @file X25519.hpp
 * @brief High-performance X25519 Diffie-Hellman key exchange.
 */

#ifndef XI_SEC_X25519_HPP
#define XI_SEC_X25519_HPP

#include "../Xi/String.hpp"

namespace Sec {

using namespace Xi;

namespace X {

class Keypair;

XI_EXPORT String& clamp(String &privateKey);
XI_EXPORT String clamp(const String &privateKey);

XI_EXPORT String generateKey();
XI_EXPORT String publicKey(const String &privateKey);
XI_EXPORT String sharedKey(const String &ourPrivate, const String &theirPublic);

class XI_EXPORT PublicKey {
private:
    mutable String _cached;
    const String* _priv = nullptr;
public:
    PublicKey() = default;
    void bind(const String *priv) { _priv = priv; _cached.clear(); }
    void set(const String &pub) { _cached = pub; }
    const String& cached() const { return _cached; }

    const String& get() const {
        if (_cached.isEmpty() && _priv && !_priv->isEmpty()) {
            _cached = X::publicKey(*_priv);
        }
        return _cached;
    }

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

    Keypair() {
        publicKey.bind(&secretKey);
    }
    Keypair(const String &priv) : secretKey(priv) {
        publicKey.bind(&secretKey);
    }
    Keypair(const Keypair &o) : secretKey(o.secretKey) {
        publicKey.bind(&secretKey);
        if (!o.publicKey.cached().isEmpty()) {
            publicKey.set(o.publicKey.cached());
        }
    }
    Keypair(Keypair &&o) noexcept : secretKey(Xi::Move(o.secretKey)) {
        publicKey.bind(&secretKey);
        publicKey.set(Xi::Move(o.publicKey.cached()));
    }
    Keypair &operator=(const Keypair &o) {
        if (this != &o) {
            secretKey = o.secretKey;
            publicKey.bind(&secretKey);
            publicKey.set(o.publicKey.cached());
        }
        return *this;
    }
    Keypair &operator=(Keypair &&o) noexcept {
        if (this != &o) {
            secretKey = Xi::Move(o.secretKey);
            publicKey.bind(&secretKey);
            publicKey.set(Xi::Move(o.publicKey.cached()));
        }
        return *this;
    }

    static Keypair generate() {
        return Keypair(X::generateKey());
    }
};

XI_EXPORT String sharedKey(const Keypair &ourKeypair, const String &theirPublic);

} // namespace X

} // namespace Sec

#endif // XI_SEC_X25519_HPP

