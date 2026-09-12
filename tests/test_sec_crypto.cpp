#include <Sec/Blake2b.hpp>
#include <Sec/Chacha20.hpp>
#include <Sec/Poly1305.hpp>
#include <Sec/AEAD.hpp>
#include <Sec/SHA256.hpp>
#include <Sec/SHA512.hpp>
#include <Sec/A2id.hpp>
#include <cstdio>
#include <cassert>

using namespace Xi;

int main() {
    std::printf("=== Running Symmetric Crypto & Hash Tests (Sec) ===\n");

    // 1. BLAKE2b Hash & HKDF
    String h1 = Sec::B2B::hash("abc", 64);
    assert(h1.size() == 64);
    String b2bHkdf = Sec::B2B::hkdf("secret_ikm", "salt_val", "info_val", 32);
    assert(b2bHkdf.size() == 32);

    // 2. ChaCha20 Stream Cipher
    String cKey = Sec::B2B::hash("secret_key_chacha", 32);
    String plaintext = "Hello Autonomous World";
    String ct = Sec::encrypt(cKey, 12345ULL, plaintext);
    String pt = Sec::decrypt(cKey, 12345ULL, ct);
    assert(pt == plaintext);

    // 3. Poly1305 Authenticator
    String pKey = Sec::B2B::hash("poly1305_key_test", 32);
    String pTag = Sec::Poly1305::hash(pKey, plaintext);
    assert(pTag.size() == 16);
    assert(Sec::Poly1305::verify(pKey, plaintext, pTag));
    assert(!Sec::Poly1305::verify(pKey, "tampered", pTag));

    // 4. AEAD (ChaCha20-Poly1305)
    Sec::AEADOptions opts;
    opts.text = "Sensitive data to seal";
    opts.ad = "Metadata headers";
    bool sealed = Sec::seal(cKey, 9999ULL, opts);
    assert(sealed);
    assert(opts.tag.size() == 16);
    bool opened = Sec::open(cKey, 9999ULL, opts);
    assert(opened);
    assert(opts.text == "Sensitive data to seal");

    // 5. SHA-256
    String sha256 = Sec::SHA256::hash("test sha256 input");
    assert(sha256.size() == 32);

    // 6. SHA-512
    String sha512 = Sec::SHA512::hash("test sha512 input");
    assert(sha512.size() == 64);

    // 7. Argon2id Key Derivation
    String a2Key = Sec::A2id::hkdf("password123", "salt_16_bytes_ok", 32, 1024, 1, 1);
    assert(a2Key.size() == 32);
    String a2Key2 = Sec::A2id::hkdf("password123", "salt_16_bytes_ok", 32, 1024, 1, 1);
    assert(a2Key == a2Key2);

    std::printf("✓ All Symmetric Crypto & Hash tests passed successfully!\n");
    return 0;
}

