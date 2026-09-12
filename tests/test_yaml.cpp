#include <Xi/Tree.hpp>
#include <Data/Yaml.hpp>
#include <cstdio>
#include <cassert>

using namespace Xi;
using namespace Data;

int main() {
    std::printf("=== Running YAML Parser & Serializer Tests ===\n");

    // 1. Verify null serialization
    Node<> nullNode;
    nullNode.isNull = true;
    assert(nullNode.isNull);
    String nullYaml = toYAML(nullNode);
    assert(nullYaml == "null");

    // 2. Verify YAML parsing into Node hierarchy
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
    assert(yamlTree.size() == 1);

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

    // 3. Verify YAML re-serialization
    String serialized = toYAML(yamlTree);
    assert(serialized.length() > 0);

    // Re-parse serialized output to verify round-trip stability
    Node<> roundtripTree;
    bool reParsed = parseYAML(serialized, roundtripTree);
    assert(reParsed);
    Node<>* rtApp = roundtripTree.get("app");
    assert(rtApp != nullptr);
    assert(dynamic_cast<Node<String>*>(rtApp->get("name"))->value == "MyApp");

    std::printf("✓ All YAML tests passed successfully!\n");
    return 0;
}

