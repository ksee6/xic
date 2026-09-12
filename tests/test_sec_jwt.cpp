#include <Sec/JWT.hpp>
#include <Xi/Tree.hpp>
#include <cstdio>
#include <cassert>

using namespace Xi;

int main() {
    std::printf("=== Running JWT (JSON Web Token) Tests ===\n");

    // 1. Build claims tree
    Node<> jwtClaims;
    jwtClaims.add(new Node<String>("sub", "user_42"));
    jwtClaims.add(new Node<String>("name", "Xi"));
    jwtClaims.add(new Node<bool>("admin", true));
    jwtClaims.add(new Node<long long>("iat", 1726000000));

    String jwtKey = "super_secret_jwt_key_2026";

    // 2. Seal token
    String token = Sec::JWT::seal(jwtClaims, jwtKey);
    assert(token.size() > 0);
    assert(token.split(".").size() == 3);

    // 3. Open valid token
    Node nd = Sec::JWT::open(token, jwtKey);
    assert(!nd.isNull);
    assert(nd.get("sub") != nullptr);
    assert(dynamic_cast<Node<String>*>(nd.get("sub"))->value == "user_42");
    assert(nd.get("name") != nullptr);
    assert(dynamic_cast<Node<String>*>(nd.get("name"))->value == "Xi");
    assert(nd.get("admin") != nullptr);
    assert(dynamic_cast<Node<bool>*>(nd.get("admin"))->value == true);
    assert(nd.get("iat") != nullptr);
    assert(dynamic_cast<Node<long long>*>(nd.get("iat"))->value == 1726000000);

    // 4. Open with wrong key -> isNull must be true
    Node invalidKeyNd = Sec::JWT::open(token, "wrong_key");
    assert(invalidKeyNd.isNull);

    // 5. Tampered token -> isNull must be true
    String tamperedToken = token + "bad";
    Node tamperedNd = Sec::JWT::open(tamperedToken, jwtKey);
    assert(tamperedNd.isNull);

    // 6. Malformed token -> isNull must be true
    Node malformedNd = Sec::JWT::open("not.a.valid.jwt.at.all", jwtKey);
    assert(malformedNd.isNull);

    std::printf("✓ All JWT tests passed successfully!\n");
    return 0;
}

