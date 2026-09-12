#include <Xi/UUID.hpp>
#include <cstdio>
#include <cassert>

using namespace Xi;

int main() {
    std::printf("=== Running UUID Tests (Versions 1-8) ===\n");

    UUID u1 = UUID::v1();
    assert(u1.version() == 1);

    UUID u3 = UUID::v3(UUID::NamespaceDNS, "example.com");
    assert(u3.version() == 3);

    UUID u4 = UUID::v4();
    assert(u4.version() == 4);

    UUID u5 = UUID::v5(UUID::NamespaceDNS, "example.com");
    assert(u5.version() == 5);

    UUID u6 = UUID::v6();
    assert(u6.version() == 6);

    UUID u7 = UUID::v7();
    assert(u7.version() == 7);

    u8 customData[16] = {0};
    UUID u8 = UUID::v8(customData);
    assert(u8.version() == 8);

    // Verify determinism of v3 and v5
    UUID u3_repeat = UUID::v3(UUID::NamespaceDNS, "example.com");
    assert(u3 == u3_repeat);

    UUID u5_repeat = UUID::v5(UUID::NamespaceDNS, "example.com");
    assert(u5 == u5_repeat);

    // Verify string serialization and parsing roundtrip
    String s4 = u4.toString();
    assert(s4.length() == 36);
    UUID parsed4 = UUID::fromString(s4);
    assert(parsed4 == u4);

    std::printf("✓ All UUID tests passed successfully!\n");
    return 0;
}

