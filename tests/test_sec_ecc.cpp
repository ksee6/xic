#include <Sec/X25519.hpp>
#include <Sec/Ed25519.hpp>
#include <cstdio>
#include <cassert>

using namespace Xi;

int main() {
    std::printf("=== Running Elliptic Curve Tests (X25519 & Ed25519) ===\n");

    // 1. X25519 Key Clamping
    String rawX;
    for (int i = 0; i < 32; ++i) rawX.push((u8)0xff);
    Sec::X::clamp(rawX);
    assert((reinterpret_cast<const u8*>(rawX.data())[0] & 7) == 0);
    assert((reinterpret_cast<const u8*>(rawX.data())[31] & 128) == 0);
    assert((reinterpret_cast<const u8*>(rawX.data())[31] & 64) == 64);

    // 2. X25519 Keypair Generation and Lazy Public Key
    String genX = Sec::X::generateKey();
    assert(genX.size() == 32);

    Sec::X::Keypair xAlice = Sec::X::Keypair::generate();
    Sec::X::Keypair xBob = Sec::X::Keypair::generate();
    assert(xAlice.secretKey.size() == 32);
    // Lazy evaluation of publicKey property on first access
    assert(xAlice.publicKey.size() == 32);
    assert(xBob.publicKey.size() == 32);

    // 3. X25519 Diffie-Hellman Shared Secret
    String sAlice = Sec::X::sharedKey(xAlice.secretKey, xBob.publicKey);
    String sBob = Sec::X::sharedKey(xBob, xAlice.publicKey);
    assert(sAlice.size() == 32);
    assert(sAlice == sBob);

    // 4. Ed25519 Signatures and Verification
    String testPriv;
    for (int i = 0; i < 32; ++i) testPriv.push((u8)1);
    String testPub = Sec::Ed::publicKey(testPriv);
    assert(testPub.size() == 32);

    String testSig = Sec::Ed::sign(testPriv, "hello");
    assert(testSig.size() == 64);
    assert(Sec::Ed::verify(testPub, "hello", testSig));
    assert(!Sec::Ed::verify(testPub, "hello_tampered", testSig));

    // 5. Ed25519 Keypair and Lazy Public Key
    Sec::Ed::Keypair edAlice = Sec::Ed::Keypair::generate();
    Sec::Ed::Keypair edBob = Sec::Ed::Keypair::generate();
    assert(edAlice.secretKey.size() == 32);
    assert(edAlice.publicKey.size() == 32);

    String doc = "Autonomous Ed25519 Document";
    String edSig = Sec::Ed::sign(edAlice.secretKey, doc);
    assert(edSig.size() == 64);
    assert(Sec::Ed::verify(edAlice.publicKey, doc, edSig));
    assert(!Sec::Ed::verify(edAlice.publicKey, "Tampered doc", edSig));

    // 6. Conversions Ed25519 -> X25519
    String convPriv = Sec::Ed::toXPrivateKey(edAlice.secretKey);
    String convPub = Sec::Ed::toXPublicKey(edAlice.publicKey);
    assert(convPriv.size() == 32);
    assert(convPub.size() == 32);
    // Birational equivalence: X::publicKey(convPriv) == convPub
    assert(Sec::X::publicKey(convPriv) == convPub);

    Sec::X::Keypair xFromEd = Sec::Ed::toXKeypair(edAlice);
    assert(xFromEd.secretKey == convPriv);
    assert(xFromEd.publicKey == convPub);

    // 7. Ed::sharedKey & Sec::sharedKeyEd
    String edShared1 = Sec::Ed::sharedKey(edAlice.secretKey, edBob.publicKey);
    String edShared2 = Sec::Ed::sharedKey(edBob, edAlice.publicKey);
    String edShared3 = Sec::sharedKeyEd(edAlice.secretKey, edBob.publicKey);
    assert(edShared1.size() == 32);
    assert(edShared1 == edShared2);
    assert(edShared1 == edShared3);

    std::printf("✓ All Elliptic Curve tests passed successfully!\n");
    return 0;
}

