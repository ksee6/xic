/**
 * @file JWT.cpp
 * @brief Implementation of JSON Web Token (JWT) HS256 sealing and verification.
 */

#include "../../include/Sec/JWT.hpp"
#include "../../include/Sec/SHA256.hpp"
#include "../../include/Data/Yaml.hpp"
#include <cstring>
#include <cstdio>

namespace Sec {

// -----------------------------------------------------------------------------
// Base64URL Encoding & Decoding (RFC 7515 / RFC 4648 §5)
// -----------------------------------------------------------------------------

static const char b64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static String base64UrlEncode(const String &in) {
    String out;
    const u8 *d = reinterpret_cast<const u8 *>(in.data());
    usz n = in.size();
    for (usz i = 0; i < n; i += 3) {
        u32 v = static_cast<u32>(d[i]) << 16;
        if (i + 1 < n) v |= static_cast<u32>(d[i + 1]) << 8;
        if (i + 2 < n) v |= static_cast<u32>(d[i + 2]);

        out.push(static_cast<u8>(b64url_chars[(v >> 18) & 63]));
        out.push(static_cast<u8>(b64url_chars[(v >> 12) & 63]));
        if (i + 1 < n) out.push(static_cast<u8>(b64url_chars[(v >> 6) & 63]));
        if (i + 2 < n) out.push(static_cast<u8>(b64url_chars[v & 63]));
    }
    return out;
}

static bool base64UrlDecode(const String &in, String &out) {
    auto decodeChar = [](u8 c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-' || c == '+') return 62;
        if (c == '_' || c == '/') return 63;
        if (c == '=') return -2; // padding
        return -1;
    };

    out.clear();
    usz n = in.size();
    usz i = 0;
    while (i < n) {
        int chunk[4] = {0, 0, 0, 0};
        int count = 0;
        int pad = 0;
        while (i < n && count < 4) {
            u8 c = static_cast<u8>(in[i++]);
            int v = decodeChar(c);
            if (v == -2) {
                pad++;
                count++;
            } else if (v >= 0) {
                chunk[count++] = v;
            } else if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                continue;
            } else {
                return false;
            }
        }
        if (count == 0) break;
        if (count == 1) return false;

        out.push(static_cast<u8>((chunk[0] << 2) | (chunk[1] >> 4)));
        if (count > 2 && pad < 2) {
            out.push(static_cast<u8>((chunk[1] << 4) | (chunk[2] >> 2)));
        }
        if (count > 3 && pad < 1) {
            out.push(static_cast<u8>((chunk[2] << 6) | chunk[3]));
        }
    }
    return true;
}

// -----------------------------------------------------------------------------
// HMAC-SHA256 (RFC 2104 / RFC 4231)
// -----------------------------------------------------------------------------

static String hmacSHA256(const String &key, const String &data) {
    u8 k[64];
    std::memset(k, 0, 64);
    if (key.size() > 64) {
        u8 h[32];
        SHA256::hash(key.data(), key.size(), h);
        std::memcpy(k, h, 32);
    } else if (key.size() > 0) {
        std::memcpy(k, key.data(), key.size());
    }

    u8 ipad[64];
    u8 opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    SHA256 inner;
    inner.update(ipad, 64);
    if (data.size() > 0) {
        inner.update(data.data(), data.size());
    }
    u8 innerDigest[32];
    inner.final(innerDigest);

    SHA256 outer;
    outer.update(opad, 64);
    outer.update(innerDigest, 32);
    u8 outerDigest[32];
    outer.final(outerDigest);

    return String(outerDigest, 32);
}

// -----------------------------------------------------------------------------
// Compact JSON Emitter for Node<void>
// -----------------------------------------------------------------------------

static String escapeJSONString(const String &s) {
    String out = "\"";
    for (usz i = 0; i < s.size(); ++i) {
        char c = static_cast<char>(s[i]);
        if (c == '\"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
            out += buf;
        } else {
            out.push(static_cast<u8>(c));
        }
    }
    out += "\"";
    return out;
}

static String nodeToJSON(const Node<void> *node) {
    if (!node || node->isNull) return "null";

    if (node->hasValue()) {
        if (auto s = dynamic_cast<const Node<String> *>(node))
            return escapeJSONString(s->value);
        if (auto i = dynamic_cast<const Node<long long> *>(node))
            return String(i->value);
        if (auto in = dynamic_cast<const Node<int> *>(node))
            return String(in->value);
        if (auto u = dynamic_cast<const Node<u64> *>(node))
            return String(u->value);
        if (auto uz = dynamic_cast<const Node<usz> *>(node))
            return String(uz->value);
        if (auto b = dynamic_cast<const Node<bool> *>(node))
            return b->value ? "true" : "false";
        if (auto f = dynamic_cast<const Node<f64> *>(node))
            return String(f->value);
        if (auto f3 = dynamic_cast<const Node<f32> *>(node))
            return String(f3->value);
        return "null";
    }

    if (node->isArray() && node->size() > 0) {
        String out = "[";
        bool first = true;
        for (usz i = 0; i < node->size(); ++i) {
            const Node<void> *c = (*node)[i];
            if (!c) continue;
            if (!first) out += ",";
            first = false;
            out += nodeToJSON(c);
        }
        out += "]";
        return out;
    }

    // Object
    String out = "{";
    bool first = true;
    for (usz i = 0; i < node->size(); ++i) {
        const Node<void> *c = (*node)[i];
        if (!c) continue;
        if (!first) out += ",";
        first = false;
        out += escapeJSONString(c->name.isEmpty() ? String(i) : c->name);
        out += ":";
        out += nodeToJSON(c);
    }
    out += "}";
    return out;
}

// -----------------------------------------------------------------------------
// JWT Implementation (HS256 only)
// -----------------------------------------------------------------------------

// {"alg":"HS256","typ":"JWT"} base64url encoded
static const char JWT_HEADER_B64[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

String JWT::seal(const Node<void> &tree, const String &key) {
    return seal(&tree, key);
}

String JWT::seal(const Node<void> *tree, const String &key) {
    if (!tree || tree->isNull) {
        return "";
    }
    String json = nodeToJSON(tree);
    return seal(json, key);
}

String JWT::seal(const String &jsonPayload, const String &key) {
    String headerB64 = JWT_HEADER_B64;
    String payloadB64 = base64UrlEncode(jsonPayload);
    String signingInput = headerB64 + "." + payloadB64;
    String sigRaw = hmacSHA256(key, signingInput);
    String sigB64 = base64UrlEncode(sigRaw);
    return signingInput + "." + sigB64;
}

Node<void> JWT::open(const String &token, const String &key) {
    Node<void> invalid;
    invalid.isNull = true;

    Array<String> parts = token.split(".");
    if (parts.size() != 3) {
        return invalid;
    }

    const String &headerB64 = parts[0];
    const String &payloadB64 = parts[1];
    const String &sigB64 = parts[2];

    if (headerB64.isEmpty() || payloadB64.isEmpty() || sigB64.isEmpty()) {
        return invalid;
    }

    // Verify HMAC-SHA256 signature in constant time
    String signingInput = headerB64 + "." + payloadB64;
    String expectedSigRaw = hmacSHA256(key, signingInput);
    String expectedSigB64 = base64UrlEncode(expectedSigRaw);

    if (sigB64.size() != expectedSigB64.size() ||
        !sigB64.constantTimeEquals(expectedSigB64, 0)) {
        return invalid;
    }

    // Decode and verify header algorithm is HS256
    String headerJson;
    if (!base64UrlDecode(headerB64, headerJson)) {
        return invalid;
    }
    Node<void> headerTree;
    if (!Data::parseJSON(headerJson, headerTree)) {
        return invalid;
    }
    Node<void> *algNode = headerTree.get("alg");
    if (!algNode) {
        return invalid;
    }
    if (auto s = dynamic_cast<Node<String> *>(algNode)) {
        if (s->value != "HS256") {
            return invalid;
        }
    } else {
        return invalid;
    }

    // Decode and parse payload JSON
    String payloadJson;
    if (!base64UrlDecode(payloadB64, payloadJson)) {
        return invalid;
    }

    Node<void> result;
    if (!Data::parseJSON(payloadJson, result)) {
        return invalid;
    }

    result.isNull = false;
    return result;
}

bool JWT::verify(const String &token, const String &key) {
    Node<void> res = open(token, key);
    return !res.isNull;
}

} // namespace Sec

