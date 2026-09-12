#include <Xi/Tree.hpp>
#include <Data/Yaml.hpp>
#include <cstdio>
#include <cassert>

using namespace Xi;
using namespace Data;

int main() {
    std::printf("=== Running Tree & YAML Integration Tests ===\n");

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

    String serialized = toYAML(yamlTree);
    assert(serialized.length() > 0);

    delete root;
    std::printf("✓ Tree & YAML tests passed successfully!\n");
    return 0;
}
