#include <Xi/Tree.hpp>
#include <Data/Yaml.hpp>
#include <cstdio>
#include <cassert>

using namespace Xi;

int main() {
    std::printf("=== Running Comprehensive Tree & Node Tests ===\n");

    // -------------------------------------------------------------------------
    // 1. Hierarchy & Parent-Child Invariants
    // -------------------------------------------------------------------------
    {
        std::printf("Testing Parent-Child Invariants...\n");
        Node<>* root = new Node<>();
        root->name = "root";

        Node<>* child1 = new Node<>();
        child1->name = "child1";

        Node<int>* child2 = new Node<int>(42);
        child2->name = "child2";

        root->add(child1);
        root->add(child2);

        assert(child1->parent == root);
        assert(child2->parent == root);
        assert(root->size() == 2);

        // Test unlinking on child deletion
        delete child1; // destructor unlinks itself from parent!
        assert(root->size() == 1);
        assert(root->get("child1") == nullptr);
        assert(root->get("child2") == child2);

        // Reparenting to another node
        Node<>* other = new Node<>();
        other->add(child2); // should unlink from root and link to other
        assert(child2->parent == other);
        assert(root->size() == 0);
        assert(other->size() == 1);

        delete root;
        delete other; // cleans up child2
    }

    // -------------------------------------------------------------------------
    // 2. Query Selector: Path, *, **, Tags (#tag), and Numbering (##x, ##first, ##last)
    // -------------------------------------------------------------------------
    {
        std::printf("Testing Modern Path Queries & Wildcards...\n");
        // Build tree:
        // root
        //   └── name
        //         └── directChild
        //               └── sub
        //                     └── Descendant
        //                           └── anyChild
        //                                 └── grandChildOfTheDescendant (#tag1, #tag2)
        Node<> root;
        root.name = "root";

        Node<>* nName = new Node<>();
        nName->name = "name";
        root.add(nName);

        Node<>* nDirect = new Node<>();
        nDirect->name = "directChild";
        nName->add(nDirect);

        Node<>* nSub = new Node<>();
        nSub->name = "sub";
        nDirect->add(nSub);

        Node<>* nDesc = new Node<>();
        nDesc->name = "Descendant";
        nSub->add(nDesc);

        Node<>* nAny = new Node<>();
        nAny->name = "anyChild";
        nDesc->add(nAny);

        Node<String>* nTarget = new Node<String>("FoundTarget");
        nTarget->name = "grandChildOfTheDescendant";
        nTarget->addTag("tag1");
        nTarget->addTag("tag2");
        nAny->add(nTarget);

        // Prompt example selector:
        // "name/directChild/**/Descendant/*/grandChildOfTheDescendant#tag1#tag2"
        Array<Node<>*> queryRes = root.query("name/directChild/**/Descendant/*/grandChildOfTheDescendant#tag1#tag2");
        assert(queryRes.size() == 1);
        assert(queryRes[0] == nTarget);

        // Testing first() and last()
        assert(root.first("name/directChild/**/Descendant/*/grandChildOfTheDescendant#tag1#tag2") == nTarget);
        assert(root.last("name/directChild/**/Descendant/*/grandChildOfTheDescendant#tag1#tag2") == nTarget);

        // Testing ** wildcard
        Array<Node<>*> allDesc = root.query("**/Descendant");
        assert(allDesc.size() == 1);
        assert(allDesc[0] == nDesc);

        // Testing ## numbering, ##first, ##last
        Node<> listNode;
        listNode.name = "items";
        Node<int>* item0 = new Node<int>(10);
        item0->name = "item";
        item0->addTag("odd");

        Node<int>* item1 = new Node<int>(20);
        item1->name = "item";
        item1->addTag("even");

        Node<int>* item2 = new Node<int>(30);
        item2->name = "item";
        item2->addTag("odd");

        listNode.add(item0);
        listNode.add(item1);
        listNode.add(item2);

        // ##0, ##1, ##2
        assert(listNode.first("##0") == item0);
        assert(listNode.first("##1") == item1);
        assert(listNode.first("##2") == item2);

        // ##first and ##last
        assert(listNode.first("##first") == item0);
        assert(listNode.first("##last") == item2);

        // Combining with tag and numbering: item#odd##0 vs item#odd##last
        assert(listNode.first("item#odd##0") == item0);
        assert(listNode.first("item#odd##last") == item2);
        assert(listNode.first("item#even##0") == item1);

        // Path with numbering: items/##last
        Node<> container;
        container.add(listNode.clone());
        assert(container.first("items/##first") != nullptr);
        assert(container.first("items/##last") != nullptr);
    }

    // -------------------------------------------------------------------------
    // 3. Type Casting as<T>()
    // -------------------------------------------------------------------------
    {
        std::printf("Testing Type Casting as<T>()...\n");
        Node<int> intNode(1234);
        intNode.name = "num";

        // Direct value type
        assert(intNode.as<int>() == 1234);
        assert(intNode.as<long long>() == 1234LL);
        assert(intNode.as<double>() == 1234.0);
        assert(intNode.as<bool>() == true);
        assert(intNode.as<String>() == "1234");

        // Pointer cast
        Node<>* basePtr = &intNode;
        assert(basePtr->as<Node<int>*>() == &intNode);
        assert(basePtr->as<Node<String>*>() == nullptr);
        assert(basePtr->as<Node<>*>() == &intNode);

        // String node to numbers
        Node<String> strNode("999");
        assert(strNode.as<String>() == "999");
        assert(strNode.as<int>() == 999);
        assert(strNode.as<double>() == 999.0);

        // Bool node
        Node<bool> boolNode(true);
        assert(boolNode.as<bool>() == true);
        assert(boolNode.as<int>() == 1);
        assert(boolNode.as<String>() == "true");
    }

    // -------------------------------------------------------------------------
    // 4. Operator [] Proxy, Chaining & Assignment/Deletion
    // -------------------------------------------------------------------------
    {
        std::printf("Testing NodeProxy, Chaining, and Assignment...\n");
        Node<> root;

        // node["name"] = x (raw value) -> creates Node<T>
        root["count"] = 42;
        assert(root["count"] != nullptr);
        assert(root["count"].as<int>() == 42);

        // Overwrite: replaces all exact matching children
        root["count"] = 100;
        assert(root["count"].as<int>() == 100);
        assert(root.size() == 1);

        // Setting a Node*
        Node<String>* titleNode = new Node<String>("Hello World");
        root["title"] = titleNode;
        assert(root["title"] != nullptr);
        assert(root["title"].as<String>() == "Hello World");

        // Chaining: node["hello"]["world"] is just node["hello/world"]
        root["hello"]["world"] = 777;
        assert(root["hello"]["world"] != nullptr);
        assert(root["hello"]["world"].as<int>() == 777);
        assert(root["hello/world"].as<int>() == 777);

        // Deep chaining read
        assert(root["hello"]["world"]->parent->name == "hello");

        // Deletion: delete node["name"]
        delete root["title"];
        assert(root["title"] == nullptr);

        // Deletion via remove(): node.remove("hello")
        root.remove("hello");
        assert(root["hello"] == nullptr);
        assert(root["hello"]["world"] == nullptr);
    }

    // -------------------------------------------------------------------------
    // 5. Virtual Properties (defineGetter / defineSetter / undefine)
    // -------------------------------------------------------------------------
    {
        std::printf("Testing Virtual Properties...\n");
        Node<> root;
        int computedValue = 50;

        root.defineGetter("computed", [&](Node<>*) {
            return new Node<int>(computedValue * 2);
        });

        root.defineSetter("computed", [&](Node<>*, Node<>* val) {
            computedValue = val->as<int>();
        });

        // Reading virtual getter
        assert(root["computed"].as<int>() == 100);

        // Writing virtual setter
        root["computed"] = 30;
        assert(computedValue == 30);
        assert(root["computed"].as<int>() == 60);

        // Undefine
        root.undefineGetter("computed");
        root.undefineSetter("computed");
        assert(root["computed"] == nullptr);
    }

    // -------------------------------------------------------------------------
    // 6. Array vs Object Detection, YAML & JSON Encoding
    // -------------------------------------------------------------------------
    {
        std::printf("Testing Array vs Object Serialization...\n");

        // Array: all children have empty names
        Node<> arrayNode;
        arrayNode.add(new Node<int>(1));
        arrayNode.add(new Node<int>(2));
        arrayNode.add(new Node<int>(3));
        assert(arrayNode.isArray());
        assert(!arrayNode.isObject());

        String yamlArray = Data::YAML::toYAML(arrayNode);
        assert(yamlArray.indexOf("- 1") != -1);
        assert(yamlArray.indexOf("- 2") != -1);
        assert(yamlArray.indexOf("- 3") != -1);

        String jsonArray = Data::YAML::toJSON(arrayNode);
        assert(jsonArray.startsWith("["));
        assert(jsonArray.indexOf("1") != -1);
        assert(jsonArray.indexOf("2") != -1);
        assert(jsonArray.endsWith("]"));

        // Object: at least one child has a name
        Node<> objectNode;
        Node<String>* prop1 = new Node<String>("val1");
        prop1->name = "key1";
        Node<int>* prop2 = new Node<int>(99);
        prop2->name = "key2";
        objectNode.add(prop1);
        objectNode.add(prop2);

        assert(!objectNode.isArray());
        assert(objectNode.isObject());

        String yamlObj = Data::YAML::toYAML(objectNode);
        assert(yamlObj.indexOf("key1: val1") != -1);
        assert(yamlObj.indexOf("key2: 99") != -1);

        String jsonObj = Data::YAML::toJSON(objectNode);
        assert(jsonObj.startsWith("{"));
        assert(jsonObj.indexOf("\"key1\": \"val1\"") != -1);
        assert(jsonObj.indexOf("\"key2\": 99") != -1);
        assert(jsonObj.endsWith("}"));

        // Mixed: one unnamed, one named -> considered object
        Node<> mixedNode;
        Node<int>* unnamed = new Node<int>(10);
        Node<int>* named = new Node<int>(20);
        named->name = "extra";
        mixedNode.add(unnamed);
        mixedNode.add(named);
        assert(!mixedNode.isArray());
        assert(mixedNode.isObject());
    }

    std::printf("✓ All Modern Tree & Node tests passed successfully!\n");
    return 0;
}
