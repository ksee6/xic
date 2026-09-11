#include <Xi/Tree.hpp>
#include <Data/Yaml.hpp>
#include <Sec/Hash.hpp>
#include <Sec/Chacha20.hpp>
#include <Sec/Poly1305.hpp>
#include <Sec/AEAD.hpp>
#include <Sec/ECDH.hpp>
#include <Sec/HKDF.hpp>
#include <Sec/SHA256.hpp>
#include <Xi/UUID.hpp>
#include <cstdio>
#include <cassert>

using namespace Xi;
using namespace Data;

int main() {
    std::printf("=== Running Comprehensive Tree, YAML, Sec & Xi Tests ===\n");

    // 1. Verify Node creation and tree building
    Node<>* root = new Node<>();
    
    Node<>* child1 = new Node<>();
    child1->name = "button";
    child1->addTag("btn");
    child1->addTag("primary");

    Node<int>* child2 = new Node<int>(42);
    child2->name = "count";

    Node<bool>* child3 = new Node<bool>(true);
    child3->name = "active";
    child3->addTag("state");

    root->add(child1);
    root->add(child2);
    root->add(child3);

    // Verify basic hierarchy
    assert(root->size() == 3);
    assert(root->get("button") == child1);
    assert(root->get("count") == child2);
    assert(root->get("active") == child3);

    // 2. Verify Query selector matching
    Array<Node<>*> queryResults = root->query("button.btn");
    assert(queryResults.length() == 1);
    assert(queryResults[0] == child1);

    assert(child1->query("button").length() == 1);
    assert(child1->query("button")[0] == child1);

    Node<>* foundNode = query(root, "active.state");
    assert(foundNode == child3);

    Array<Node<>*> allStates = queryAll(root, ".state");
    assert(allStates.length() == 1);
    assert(allStates[0] == child3);

    // 3. Verify Array vs Object detection & isNull
    Node<> arrNode;
    Node<String>* item1 = new Node<String>("first");
    Node<String>* item2 = new Node<String>("second");
    arrNode.add(item1);
    arrNode.add(item2);
    assert(arrNode.isArray());
    assert(!arrNode.isObject());

    Node<> nullNode;
    nullNode.isNull = true;
    assert(nullNode.isNull);
    String nullYaml = toYAML(nullNode);
    assert(nullYaml == "null");

    // 4. Verify YAML parsing and serialization with Node
    String yamlInput = 
        "app:\n"
        "  name: MyApp\n"
        "  debug: true\n"
        "  threads: 8\n"
        "  servers:\n"
        "    - 192.168.1.1\n"
        "    - 192.168.1.2\n";

    Node<> yamlTree;
    bool parsed = parseYAML(yamlInput, yamlTree);
    assert(parsed);
    std::printf("yamlTree size: %zu\n", yamlTree.size());

    Node<>* appBranch = yamlTree.get("app");
    assert(appBranch != nullptr);

    Node<>* nameNode = appBranch->get("name");
    assert(nameNode != nullptr);
    Node<String>* nameStr = dynamic_cast<Node<String>*>(nameNode);
    assert(nameStr != nullptr);
    assert(nameStr->value == "MyApp");

    Node<>* debugNode = appBranch->get("debug");
    assert(debugNode != nullptr);
    Node<bool>* debugBool = dynamic_cast<Node<bool>*>(debugNode);
    assert(debugBool != nullptr);
    assert(debugBool->value == true);

    Node<>* threadsNode = appBranch->get("threads");
    assert(threadsNode != nullptr);
    Node<long long>* threadsInt = dynamic_cast<Node<long long>*>(threadsNode);
    assert(threadsInt != nullptr);
    assert(threadsInt->value == 8);

    String serialized = toYAML(yamlTree);
    assert(serialized.length() > 0);
    std::printf("Serialized tree to YAML:\n%s\n", serialized.c_str());

    // 5. Verify Cryptographic Subsystem (Sec)
    std::printf("Verifying Sec (BLAKE2b, ChaCha20, Poly1305, AEAD, ECDH, SHA256)...\n");
    
    // BLAKE2b
    String h1 = Sec::hash("abc", 64);
    assert(h1.size() == 64);

    // ChaCha20
    String cKey = Sec::hash("secret_key_chacha", 32);
    String plaintext = "Hello Autonomous World";
    String ct = Sec::encrypt(cKey, 12345ULL, plaintext);
    String pt = Sec::decrypt(cKey, 12345ULL, ct);
    assert(pt == plaintext);

    // Poly1305
    String pKey = Sec::hash("poly1305_key_test", 32);
    String pTag = Sec::sign(pKey, plaintext);
    assert(pTag.size() == 16);
    assert(Sec::verify(pKey, plaintext, pTag));
    assert(!Sec::verify(pKey, "tampered", pTag));

    // AEAD (ChaCha20-Poly1305)
    Sec::AEADOptions opts;
    opts.text = "Sensitive data to seal";
    opts.ad = "Metadata headers";
    bool sealed = Sec::seal(cKey, 9999ULL, opts);
    assert(sealed);
    assert(opts.tag.size() == 16);
    bool opened = Sec::open(cKey, 9999ULL, opts);
    assert(opened);
    assert(opts.text == "Sensitive data to seal");

    // X25519 ECDH
    Sec::KeyPair alice = Sec::generateKeyPair();
    Sec::KeyPair bob = Sec::generateKeyPair();
    assert(alice.publicKey.size() == 32);
    assert(bob.publicKey.size() == 32);
    String sAlice = Sec::sharedKey(alice.secretKey, bob.publicKey);
    String sBob = Sec::sharedKey(bob.secretKey, alice.publicKey);
    assert(sAlice.size() == 32);
    assert(sAlice == sBob);

    // SignX & VerifyX
    String sig = Sec::signX(alice.secretKey, "Document to be signed");
    assert(sig.size() == 64);
    assert(Sec::verifyX(alice.publicKey, "Document to be signed", sig));
    assert(!Sec::verifyX(alice.publicKey, "Tampered doc", sig));

    // SHA-256
    String sha = Sec::hashSHA256("test sha256 input");
    assert(sha.size() == 32);

    // 6. Verify UUID all versions
    UUID u1 = UUID::v1(); assert(u1.version() == 1);
    UUID u3 = UUID::v3(UUID::NamespaceDNS, "example.com"); assert(u3.version() == 3);
    UUID u4 = UUID::v4(); assert(u4.version() == 4);
    UUID u5 = UUID::v5(UUID::NamespaceDNS, "example.com"); assert(u5.version() == 5);
    UUID u6 = UUID::v6(); assert(u6.version() == 6);
    UUID u7 = UUID::v7(); assert(u7.version() == 7);
    u8 customData[16] = {0};
    UUID u8 = UUID::v8(customData); assert(u8.version() == 8);

    delete root;
    std::printf("=== All Comprehensive Tests Passed Successfully! ===\n");
    return 0;
}
