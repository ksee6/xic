#include <Xi/Tree.hpp>
#include <cstdio>
#include <cassert>

using namespace Xi;

int main() {
    std::printf("=== Running Tree & Node Tests ===\n");

    // 1. Node creation and tree building
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

    // 2. Query selector matching
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

    // 3. Array vs Object detection & isNull
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

    delete root;
    std::printf("✓ All Tree & Node tests passed successfully!\n");
    return 0;
}

