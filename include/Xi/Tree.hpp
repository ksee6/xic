/**
 * @file Tree.hpp
 * @brief Modern hierarchical tree structure with CSS query selector support for the Xi framework.
 */

#ifndef XI_CORE_TREE_HPP
#define XI_CORE_TREE_HPP

#include "Array.hpp"
#include "String.hpp"

namespace Xi {

// -------------------------------------------------------------------------
// SFINAE Helpers & Type Name Extraction
// -------------------------------------------------------------------------

template <typename T> class HasParseHydrate {
private:
  typedef char YesType[1];
  typedef char NoType[2];
  template <typename C> static YesType &test(decltype(&C::parseHydrate));
  template <typename C> static NoType &test(...);

public:
  enum { value = sizeof(test<T>(0)) == sizeof(YesType) };
};

template <typename T> String demangle_type_name() {
#if defined(__GNUC__) || defined(__clang__)
  String pretty = __PRETTY_FUNCTION__;
  long long eq = pretty.find("=");
  if (eq != -1) {
    long long bracket = pretty.indexOf(']', eq);
    if (bracket != -1) {
      String name = pretty.substring(eq + 1, bracket).trim();
      long long colon = name.indexOf("::");
      while (colon != -1) {
        name = name.substring(colon + 2);
        colon = name.indexOf("::");
      }
      return name;
    }
  }
  return "";
#elif defined(_MSC_VER)
  String sig = __FUNCSIG__;
  long long arrow = sig.indexOf('<');
  if (arrow != -1) {
    long long end = sig.indexOf('>', arrow);
    String name = sig.substring(arrow + 1, end).trim();
    long long colon = name.indexOf("::");
    while (colon != -1) {
      name = name.substring(colon + 2);
      colon = name.indexOf("::");
    }
    if (name.startsWith("class "))
      return name.substring(6);
    if (name.startsWith("struct "))
      return name.substring(7);
    return name;
  }
  return "";
#else
  return "UnknownType";
#endif
}

// -------------------------------------------------------------------------
// Forward Declaration & Selector Definitions
// -------------------------------------------------------------------------

template <typename T = void>
class Node;

enum class Combinator {
  NoCombinator,
  Descendant,
  Child
};

struct SelectorPart {
  String tag;
  Array<String> classes;
  Combinator relationToLeft = Combinator::NoCombinator;

  bool matches(const Node<void> *item) const;
};

// -------------------------------------------------------------------------
// Node<void> (Base Node)
// -------------------------------------------------------------------------

template <>
class XI_EXPORT Node<void> {
protected:
  static Array<SelectorPart> parse_selector(const String &queryStr);
  static bool verify_chain(const Node<void> *item, const Array<SelectorPart> &chain);

  template <typename... Ts>
  void query_recursive(const Array<SelectorPart> &chain, Array<Node<void> *> &out);

public:
  Node<void> *parent = nullptr;
  String name;
  Array<String> tags;
  Array<Node<void> *> children;
  bool isNull = false;

  Node() = default;

  Node(const Node<void> &o)
      : parent(nullptr), name(o.name), tags(o.tags), isNull(o.isNull) {
    for (usz i = 0; i < o.children.size(); ++i) {
      if (o.children[i]) add(o.children[i]->clone());
    }
  }

  Node(Node<void> &&o) noexcept
      : parent(o.parent), name(Xi::Move(o.name)), tags(Xi::Move(o.tags)),
        children(Xi::Move(o.children)), isNull(o.isNull) {
    o.parent = nullptr;
    o.children.clear();
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i]) children[i]->parent = this;
    }
  }

  Node<void> &operator=(const Node<void> &o) {
    if (this != &o) {
      for (usz i = 0; i < children.size(); ++i) {
        delete children[i];
      }
      children.clear();
      parent = nullptr;
      name = o.name;
      tags = o.tags;
      isNull = o.isNull;
      for (usz i = 0; i < o.children.size(); ++i) {
        if (o.children[i]) add(o.children[i]->clone());
      }
    }
    return *this;
  }

  Node<void> &operator=(Node<void> &&o) noexcept {
    if (this != &o) {
      for (usz i = 0; i < children.size(); ++i) {
        delete children[i];
      }
      children.clear();
      parent = o.parent;
      name = Xi::Move(o.name);
      tags = Xi::Move(o.tags);
      children = Xi::Move(o.children);
      isNull = o.isNull;
      o.parent = nullptr;
      o.children.clear();
      for (usz i = 0; i < children.size(); ++i) {
        if (children[i]) children[i]->parent = this;
      }
    }
    return *this;
  }

  virtual ~Node() {
    for (usz i = 0; i < children.size(); ++i) {
      delete children[i];
    }
  }

  // Value check
  virtual bool hasValue() const { return false; }

  // Tag manipulation
  bool hasTag(const String &tag) const {
    for (usz i = 0; i < tags.size(); ++i) {
      if (tags[i] == tag) return true;
    }
    return false;
  }

  bool hasClass(const char *cls) const {
    return hasTag(String(cls));
  }

  Node<void> *addTag(const String &tag) {
    if (!hasTag(tag)) tags.push(tag);
    return this;
  }

  Node<void> *addClass(const char *cls) {
    return addTag(String(cls));
  }

  Array<String> getClasses() const { return tags; }
  String getName() const { return name; }
  void setName(const String &newName) { name = newName; }

  // Child management
  Node<void> *add(Node<void> *child) {
    if (!child) return nullptr;
    child->parent = this;
    children.push(child);
    return child;
  }

  Node<void> *addChild(Node<void> *child) {
    return add(child);
  }

  template <typename U>
  Node<U> *add(Node<U> *child) {
    if (!child) return nullptr;
    child->parent = this;
    children.push(child);
    return child;
  }

  template <typename U>
  Node<U> *addChild(Node<U> *child) {
    return add(child);
  }

  Node<void> *getChild(usz index) const {
    return (index < children.size()) ? children[index] : nullptr;
  }

  usz getChildCount() const { return children.size(); }

  void removeChild(Node<void> *child) {
    long long idx = -1;
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i] == child) {
        idx = i;
        break;
      }
    }
    if (idx != -1) {
      children.splice(idx, 1);
      child->parent = nullptr;
    }
  }

  usz size() const { return children.size(); }
  usz length() const { return children.size(); }
  bool isEmpty() const { return children.size() == 0; }

  // Array vs Object detection
  bool isArray() const {
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i] && !children[i]->name.isEmpty()) return false;
    }
    return true;
  }

  bool isObject() const { return !isArray(); }

  // Element access
  Node<void> *operator[](usz index) const {
    return (index < children.size()) ? children[index] : nullptr;
  }

  Node<void> *operator[](const String &key) const { return get(key); }

  Node<void> *get(const String &key) const {
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i] && children[i]->name == key)
        return children[i];
    }
    return nullptr;
  }

  template <typename V>
  Node<V> *get(const String &key) const {
    for (usz i = 0; i < children.size(); ++i) {
      Node<void> *child = children[i];
      if (child && child->name == key) {
        if (auto *t = dynamic_cast<Node<V> *>(child))
          return t;
      }
    }
    return nullptr;
  }

  template <typename V>
  Node<V> *get() const {
    for (usz i = 0; i < children.size(); ++i) {
      if (auto *t = dynamic_cast<Node<V> *>(children[i]))
        return t;
    }
    return nullptr;
  }

  Node<void> *get() const {
    return (children.size() > 0) ? children[0] : nullptr;
  }

  virtual Node<void> *clone() const {
    Node<void> *res = new Node<void>();
    res->name = name;
    res->tags = tags;
    res->isNull = isNull;
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i]) res->add(children[i]->clone());
    }
    return res;
  }

  // CSS Queries
  template <typename T> static bool is_type(const Node<void> *item) {
    return dynamic_cast<const T *>(item) != nullptr;
  }

  template <typename T, typename... Rest>
  static bool check_types(const Node<void> *item) {
    if (!is_type<T>(item)) return false;
    if constexpr (sizeof...(Rest) > 0) return check_types<Rest...>(item);
    return true;
  }

  template <typename... Ts>
  Array<Node<void> *> query(const String &selector);

  template <typename... Ts>
  Node<void> *find(const String &selector) {
    Array<Node<void> *> res = query<Ts...>(selector);
    return (res.length() > 0) ? res[0] : nullptr;
  }

  Array<Node<void> *> flatten();
};

using NodeBase = Node<void>;

// -------------------------------------------------------------------------
// Node<T> (Leaf Node with value)
// -------------------------------------------------------------------------

template <typename T>
class XI_EXPORT Node : public Node<void> {
public:
  T value;

  Node() : Node<void>() {}
  Node(const T &v) : Node<void>(), value(v) {}
  Node(const String &n, const T &v) : Node<void>(), value(v) { name = n; }

  Node(const Node<T> &o) : Node<void>(o), value(o.value) {}
  Node(Node<T> &&o) noexcept : Node<void>(Xi::Move(o)), value(Xi::Move(o.value)) {}

  Node<T> &operator=(const Node<T> &o) {
    if (this != &o) {
      Node<void>::operator=(o);
      value = o.value;
    }
    return *this;
  }

  Node<T> &operator=(Node<T> &&o) noexcept {
    if (this != &o) {
      Node<void>::operator=(Xi::Move(o));
      value = Xi::Move(o.value);
    }
    return *this;
  }

  virtual ~Node() override = default;

  virtual bool hasValue() const override { return true; }

  virtual Node<void> *clone() const override {
    Node<T> *res = new Node<T>(value);
    res->name = name;
    res->tags = tags;
    res->isNull = isNull;
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i]) res->add(children[i]->clone());
    }
    return res;
  }
};

// Deduction guides for C++17 CTAD
Node() -> Node<void>;
template <typename T> Node(const T &) -> Node<T>;
template <typename T> Node(const String &, const T &) -> Node<T>;

// -------------------------------------------------------------------------
// Selector Implementations
// -------------------------------------------------------------------------

inline Array<SelectorPart> Node<void>::parse_selector(const String &queryStr) {
  Array<SelectorPart> parts;
  if (queryStr.length() == 0) return parts;
  Array<String> tokens = queryStr.split(" ");
  SelectorPart current;
  Combinator pendingComb = Combinator::Descendant;

  for (usz i = 0; i < tokens.length(); ++i) {
    String t = tokens[i];
    if (t == ">") {
      pendingComb = Combinator::Child;
      continue;
    }
    Array<String> sub = t.split(".");
    current.tag = (t.c_str()[0] != '.') ? sub[0] : "";
    current.classes.clear();
    for (usz k = 1; k < sub.length(); ++k)
      if (sub[k].length() > 0)
        current.classes.push(sub[k]);
    current.relationToLeft = pendingComb;
    parts.push(Xi::Move(current));
    pendingComb = Combinator::Descendant;
  }
  return parts;
}

inline bool Node<void>::verify_chain(const Node<void> *item, const Array<SelectorPart> &chain) {
  if (chain.length() == 0) return true;
  long long idx = chain.length() - 1;
  if (!chain[idx].matches(item)) return false;

  const Node<void> *curr = item;
  while (idx > 0 && curr) {
    const SelectorPart &part = chain[idx];
    const SelectorPart &prev = chain[idx - 1];

    if (part.relationToLeft == Combinator::Child) {
      curr = curr->parent;
      if (!curr || !prev.matches(curr)) return false;
    } else if (part.relationToLeft == Combinator::Descendant) {
      bool found = false;
      while (curr->parent) {
        curr = curr->parent;
        if (prev.matches(curr)) {
          found = true;
          break;
        }
      }
      if (!found) return false;
    }
    idx--;
  }
  return (idx == 0);
}

template <typename... Ts>
void Node<void>::query_recursive(const Array<SelectorPart> &chain, Array<Node<void> *> &out) {
  bool typeMatch = true;
  if constexpr (sizeof...(Ts) > 0) {
    typeMatch = Node<void>::check_types<Ts...>(this);
  }
  if (typeMatch && (chain.length() == 0 || verify_chain(this, chain)))
    out.push(this);
  for (usz i = 0; i < children.size(); ++i) {
    if (Node<void> *child = children[i])
      child->query_recursive<Ts...>(chain, out);
  }
}

template <typename... Ts>
Array<Node<void> *> Node<void>::query(const String &selector) {
  Array<Node<void> *> results;
  Array<SelectorPart> chain = parse_selector(selector);
  this->query_recursive<Ts...>(chain, results);
  return results;
}

inline Array<Node<void> *> Node<void>::flatten() {
  Array<Node<void> *> out;
  Array<SelectorPart> empty;
  for (usz i = 0; i < children.size(); ++i) {
    if (children[i])
      children[i]->query_recursive<>(empty, out);
  }
  return out;
}

inline bool SelectorPart::matches(const Node<void> *item) const {
  if (!item) return false;
  if (tag.length() > 0 && tag != "*" && item->name != tag) return false;
  for (usz i = 0; i < classes.length(); ++i)
    if (!item->hasTag(classes[i])) return false;
  return true;
}

// Global Free Functions
template <typename... Ts>
inline Array<Node<void> *> queryAll(Node<void> *root, const String &selector) {
  if (!root) return {};
  return root->query<Ts...>(selector);
}

template <typename... Ts>
inline Node<void> *query(Node<void> *root, const String &selector) {
  if (!root) return nullptr;
  return root->find<Ts...>(selector);
}

} // namespace Xi

#endif // XI_CORE_TREE_HPP
