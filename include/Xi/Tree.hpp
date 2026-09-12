/**
 * @file Tree.hpp
 * @brief Modern hierarchical tree structure with filesystem-like query selector,
 *        proxy indexing, virtual properties, and type casting for the Xi framework.
 */

#ifndef XI_CORE_TREE_HPP
#define XI_CORE_TREE_HPP

#include "Array.hpp"
#include "String.hpp"
#include "Func.hpp"
#include <cstdlib>
#include <type_traits>
#include <typeinfo>

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
// Forward Declarations
// -------------------------------------------------------------------------

template <typename T = void> class Node;
class NodeProxy;

// -------------------------------------------------------------------------
// Selector Segment & Virtual Property Definitions
// -------------------------------------------------------------------------

struct SelectorSegment {
  String name;
  Array<String> tags;
  int index = -2; // -2: no index, -1: ##last, >= 0: ##<num> or ##first (0)
  bool isDoubleStar = false;

  bool matchesNameAndTags(const Node<void> *item) const;
};

struct VirtualProp {
  String selector;
  Func<Node<void> *(Node<void> *)> getter;
  Func<void(Node<void> *, Node<void> *)> setter;
};

// -------------------------------------------------------------------------
// Node<void> (Base Node)
// -------------------------------------------------------------------------

template <>
class XI_EXPORT Node<void> {
protected:
  static Array<SelectorSegment> parse_path(const String &queryStr);
  static void collect_all_descendants(Node<void> *curr, Array<Node<void> *> &out);
  static void query_step(Node<void> *curr, usz segIdx,
                         const Array<SelectorSegment> &segments,
                         Array<Node<void> *> &out);

public:
  Node<void> *parent = nullptr;
  String name;
  Array<String> tags;
  Array<Node<void> *> children;
  bool isNull = false;
  Array<VirtualProp> *_virtualProps = nullptr;

  Node() = default;

  Node(const Node<void> &o)
      : parent(nullptr), name(o.name), tags(o.tags), isNull(o.isNull) {
    for (usz i = 0; i < o.children.size(); ++i) {
      if (o.children[i]) add(o.children[i]->clone());
    }
    if (o._virtualProps) {
      _virtualProps = new Array<VirtualProp>(*o._virtualProps);
    }
  }

  Node(Node<void> &&o) noexcept
      : parent(o.parent), name(Xi::Move(o.name)), tags(Xi::Move(o.tags)),
        children(Xi::Move(o.children)), isNull(o.isNull),
        _virtualProps(o._virtualProps) {
    o.parent = nullptr;
    o.children.clear();
    o._virtualProps = nullptr;
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i]) children[i]->parent = this;
    }
  }

  Node<void> &operator=(const Node<void> &o) {
    if (this != &o) {
      for (usz i = 0; i < children.size(); ++i) {
        if (children[i]) {
          children[i]->parent = nullptr;
          delete children[i];
        }
      }
      children.clear();
      if (_virtualProps) {
        delete _virtualProps;
        _virtualProps = nullptr;
      }
      parent = nullptr;
      name = o.name;
      tags = o.tags;
      isNull = o.isNull;
      for (usz i = 0; i < o.children.size(); ++i) {
        if (o.children[i]) add(o.children[i]->clone());
      }
      if (o._virtualProps) {
        _virtualProps = new Array<VirtualProp>(*o._virtualProps);
      }
    }
    return *this;
  }

  Node<void> &operator=(Node<void> &&o) noexcept {
    if (this != &o) {
      for (usz i = 0; i < children.size(); ++i) {
        if (children[i]) {
          children[i]->parent = nullptr;
          delete children[i];
        }
      }
      children.clear();
      if (_virtualProps) {
        delete _virtualProps;
        _virtualProps = nullptr;
      }
      parent = o.parent;
      name = Xi::Move(o.name);
      tags = Xi::Move(o.tags);
      children = Xi::Move(o.children);
      isNull = o.isNull;
      _virtualProps = o._virtualProps;
      o.parent = nullptr;
      o.children.clear();
      o._virtualProps = nullptr;
      for (usz i = 0; i < children.size(); ++i) {
        if (children[i]) children[i]->parent = this;
      }
    }
    return *this;
  }

  virtual ~Node() {
    if (parent) {
      parent->unlinkChild(this);
      parent = nullptr;
    }
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i]) {
        children[i]->parent = nullptr;
        delete children[i];
      }
    }
    children.clear();
    if (_virtualProps) {
      delete _virtualProps;
      _virtualProps = nullptr;
    }
  }

  // Value check & conversions
  virtual bool hasValue() const { return false; }
  virtual String toString() const { return ""; }
  virtual long long toInt() const { return 0; }
  virtual double toDouble() const { return 0.0; }
  virtual bool toBool() const { return false; }
  virtual void *rawValuePtr() { return nullptr; }
  virtual const void *rawValuePtr() const { return nullptr; }
  virtual const std::type_info &typeInfo() const { return typeid(void); }

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
    if (child->parent && child->parent != this) {
      child->parent->unlinkChild(child);
    }
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
    if (child->parent && child->parent != this) {
      child->parent->unlinkChild(child);
    }
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

  void unlinkChild(Node<void> *child) {
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i] == child) {
        children.splice(i, 1);
        child->parent = nullptr;
        break;
      }
    }
  }

  void removeChild(Node<void> *child) {
    unlinkChild(child);
  }

  void remove(const String &selector);

  usz size() const { return children.size(); }
  usz length() const { return children.size(); }
  bool isEmpty() const { return children.size() == 0; }

  // Array vs Object detection
  // If all children have empty names, it is an array; if one has a name, it is an object
  bool isArray() const {
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i] && !children[i]->name.isEmpty()) return false;
    }
    return true;
  }

  bool isObject() const { return !isArray(); }

  // Element access
  Node<void> *operator[](usz index) {
    return (index < children.size()) ? children[index] : nullptr;
  }
  Node<void> *operator[](usz index) const {
    return (index < children.size()) ? children[index] : nullptr;
  }
  Node<void> *operator[](int index) {
    return (index >= 0 && static_cast<usz>(index) < children.size()) ? children[static_cast<usz>(index)] : nullptr;
  }
  Node<void> *operator[](int index) const {
    return (index >= 0 && static_cast<usz>(index) < children.size()) ? children[static_cast<usz>(index)] : nullptr;
  }
  Node<void> *operator[](long long index) {
    return (index >= 0 && static_cast<usz>(index) < children.size()) ? children[static_cast<usz>(index)] : nullptr;
  }
  Node<void> *operator[](long long index) const {
    return (index >= 0 && static_cast<usz>(index) < children.size()) ? children[static_cast<usz>(index)] : nullptr;
  }

  NodeProxy operator[](const String &key);
  NodeProxy operator[](const char *key);
  const NodeProxy operator[](const String &key) const;
  const NodeProxy operator[](const char *key) const;

  Node<void> *get(const String &key) const {
    // Check virtual getter first
    if (_virtualProps) {
      for (usz i = 0; i < _virtualProps->size(); ++i) {
        if ((*_virtualProps)[i].selector == key && (*_virtualProps)[i].getter.isValid()) {
          return (*_virtualProps)[i].getter(const_cast<Node<void> *>(this));
        }
      }
    }
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
    if (_virtualProps) {
      res->_virtualProps = new Array<VirtualProp>(*_virtualProps);
    }
    return res;
  }

  // Type Casting as<T>()
  template <typename T>
  T as() {
    using CleanT = typename Xi::Decay<T>::Type;
    if constexpr (std::is_pointer_v<T>) {
      return dynamic_cast<T>(this);
    } else if constexpr (std::is_same_v<CleanT, String>) {
      return toString();
    } else if constexpr (std::is_same_v<CleanT, bool>) {
      return toBool();
    } else if constexpr (std::is_integral_v<CleanT>) {
      return static_cast<CleanT>(toInt());
    } else if constexpr (std::is_floating_point_v<CleanT>) {
      return static_cast<CleanT>(toDouble());
    } else {
      if (auto *typed = dynamic_cast<Node<CleanT> *>(this)) {
        return typed->value;
      }
      return T{};
    }
  }

  template <typename T>
  T as() const {
    return const_cast<Node<void> *>(this)->as<T>();
  }

  // Queries
  template <typename... Ts>
  Array<Node<void> *> query(const String &selector);

  template <typename... Ts>
  Node<void> *first(const String &selector) {
    Array<Node<void> *> res = query<Ts...>(selector);
    return (res.length() > 0) ? res[0] : nullptr;
  }

  template <typename... Ts>
  Node<void> *last(const String &selector) {
    Array<Node<void> *> res = query<Ts...>(selector);
    return (res.length() > 0) ? res[res.length() - 1] : nullptr;
  }

  template <typename... Ts>
  Node<void> *find(const String &selector) {
    return first<Ts...>(selector);
  }

  Array<Node<void> *> flatten();

  // Virtual Properties
  template <typename F>
  Node<void> *defineGetter(const String &selector, F &&fn) {
    if (!_virtualProps) _virtualProps = new Array<VirtualProp>();
    VirtualProp *vp = nullptr;
    for (usz i = 0; i < _virtualProps->size(); ++i) {
      if ((*_virtualProps)[i].selector == selector) {
        vp = &(*_virtualProps)[i];
        break;
      }
    }
    if (!vp) {
      VirtualProp newVp;
      newVp.selector = selector;
      _virtualProps->push(newVp);
      vp = &(*_virtualProps)[_virtualProps->size() - 1];
    }

    using CleanF = typename Xi::Decay<F>::Type;
    vp->getter = [f = std::forward<F>(fn)](Node<void> *self) -> Node<void> * {
      if constexpr (std::is_invocable_v<CleanF, Node<void> *>) {
        using Ret = std::invoke_result_t<CleanF, Node<void> *>;
        if constexpr (std::is_pointer_v<Ret>) {
          return f(self);
        } else {
          return new Node<Ret>(f(self));
        }
      } else if constexpr (std::is_invocable_v<CleanF>) {
        using Ret = std::invoke_result_t<CleanF>;
        if constexpr (std::is_pointer_v<Ret>) {
          return f();
        } else {
          return new Node<Ret>(f());
        }
      } else {
        return nullptr;
      }
    };
    return this;
  }

  template <typename F>
  Node<void> *defineSetter(const String &selector, F &&fn) {
    if (!_virtualProps) _virtualProps = new Array<VirtualProp>();
    VirtualProp *vp = nullptr;
    for (usz i = 0; i < _virtualProps->size(); ++i) {
      if ((*_virtualProps)[i].selector == selector) {
        vp = &(*_virtualProps)[i];
        break;
      }
    }
    if (!vp) {
      VirtualProp newVp;
      newVp.selector = selector;
      _virtualProps->push(newVp);
      vp = &(*_virtualProps)[_virtualProps->size() - 1];
    }

    using CleanF = typename Xi::Decay<F>::Type;
    vp->setter = [f = std::forward<F>(fn)](Node<void> *self, Node<void> *val) {
      if constexpr (std::is_invocable_v<CleanF, Node<void> *, Node<void> *>) {
        f(self, val);
      } else if constexpr (std::is_invocable_v<CleanF, Node<void> *>) {
        f(val);
      }
    };
    return this;
  }

  Node<void> *undefineGetter(const String &selector) {
    if (!_virtualProps) return this;
    for (usz i = 0; i < _virtualProps->size(); ++i) {
      if ((*_virtualProps)[i].selector == selector) {
        (*_virtualProps)[i].getter = Func<Node<void> *(Node<void> *)>();
        if (!(*_virtualProps)[i].setter.isValid()) {
          _virtualProps->splice(i, 1);
        }
        break;
      }
    }
    return this;
  }

  Node<void> *undefineSetter(const String &selector) {
    if (!_virtualProps) return this;
    for (usz i = 0; i < _virtualProps->size(); ++i) {
      if ((*_virtualProps)[i].selector == selector) {
        (*_virtualProps)[i].setter = Func<void(Node<void> *, Node<void> *)>();
        if (!(*_virtualProps)[i].getter.isValid()) {
          _virtualProps->splice(i, 1);
        }
        break;
      }
    }
    return this;
  }
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
  virtual void *rawValuePtr() override { return &value; }
  virtual const void *rawValuePtr() const override { return &value; }
  virtual const std::type_info &typeInfo() const override { return typeid(T); }

  virtual String toString() const override {
    if constexpr (std::is_same_v<T, String>) {
      return value;
    } else if constexpr (std::is_same_v<T, bool>) {
      return value ? "true" : "false";
    } else if constexpr (std::is_integral_v<T>) {
      return String(static_cast<long long>(value));
    } else if constexpr (std::is_floating_point_v<T>) {
      return String(static_cast<f64>(value));
    } else if constexpr (std::is_same_v<T, const char *>) {
      return String(value);
    } else {
      return "";
    }
  }

  virtual long long toInt() const override {
    if constexpr (std::is_same_v<T, String>) {
      return atoll(value.c_str());
    } else if constexpr (std::is_same_v<T, bool>) {
      return value ? 1 : 0;
    } else if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T>) {
      return static_cast<long long>(value);
    } else {
      return 0;
    }
  }

  virtual double toDouble() const override {
    if constexpr (std::is_same_v<T, String>) {
      return atof(value.c_str());
    } else if constexpr (std::is_same_v<T, bool>) {
      return value ? 1.0 : 0.0;
    } else if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T>) {
      return static_cast<double>(value);
    } else {
      return 0.0;
    }
  }

  virtual bool toBool() const override {
    if constexpr (std::is_same_v<T, bool>) {
      return value;
    } else if constexpr (std::is_same_v<T, String>) {
      return value == "true" || value == "1";
    } else if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T>) {
      return value != 0;
    } else {
      return false;
    }
  }

  virtual Node<void> *clone() const override {
    Node<T> *res = new Node<T>(value);
    res->name = name;
    res->tags = tags;
    res->isNull = isNull;
    for (usz i = 0; i < children.size(); ++i) {
      if (children[i]) res->add(children[i]->clone());
    }
    if (_virtualProps) {
      res->_virtualProps = new Array<VirtualProp>(*_virtualProps);
    }
    return res;
  }
};

// Deduction guides for C++17 CTAD
Node() -> Node<void>;
template <typename T> Node(const T &) -> Node<T>;
template <typename T> Node(const String &, const T &) -> Node<T>;

// -------------------------------------------------------------------------
// NodeProxy Implementation
// -------------------------------------------------------------------------

class XI_EXPORT NodeProxy {
private:
  Node<void> *_root = nullptr;
  String _path;

  Node<void> *getOrCreateParent(String &outLeaf) {
    if (!_root) return nullptr;
    long long slash = -1;
    for (long long i = static_cast<long long>(_path.length()) - 1; i >= 0; --i) {
      if (_path[i] == '/') {
        slash = i;
        break;
      }
    }
    if (slash == -1) {
      outLeaf = _path;
      return _root;
    }
    String parentPath = _path.substring(0, slash);
    outLeaf = _path.substring(slash + 1);

    Array<String> segs = parentPath.split("/");
    Node<void> *curr = _root;
    for (usz i = 0; i < segs.size(); ++i) {
      String s = segs[i].trim();
      if (s.isEmpty()) continue;
      Node<void> *next = curr->get(s);
      if (!next) {
        next = new Node<void>();
        next->name = s;
        curr->add(next);
      }
      curr = next;
    }
    return curr;
  }

  bool checkVirtualSetter(Node<void> *valNode) {
    if (!_root || !_root->_virtualProps) return false;
    for (usz i = 0; i < _root->_virtualProps->size(); ++i) {
      if ((*_root->_virtualProps)[i].selector == _path && (*_root->_virtualProps)[i].setter.isValid()) {
        (*_root->_virtualProps)[i].setter(_root, valNode);
        return true;
      }
    }
    return false;
  }

public:
  NodeProxy(Node<void> *root, const String &path) : _root(root), _path(path) {}

  NodeProxy operator[](const String &sub) const {
    String p = _path.isEmpty() ? sub : (_path + "/" + sub);
    return NodeProxy(_root, p);
  }

  NodeProxy operator[](const char *sub) const {
    return operator[](String(sub));
  }

  Node<void> *resolve() const {
    if (!_root) return nullptr;
    // 1. Virtual getter check
    if (_root->_virtualProps) {
      for (usz i = 0; i < _root->_virtualProps->size(); ++i) {
        if ((*_root->_virtualProps)[i].selector == _path && (*_root->_virtualProps)[i].getter.isValid()) {
          return (*_root->_virtualProps)[i].getter(_root);
        }
      }
    }
    // 2. Fast path: single plain name without query characters
    if (_path.indexOf('/') == -1 && _path.indexOf('*') == -1 && _path.indexOf('#') == -1) {
      for (usz i = 0; i < _root->children.size(); ++i) {
        if (_root->children[i] && _root->children[i]->name == _path)
          return _root->children[i];
      }
      return nullptr;
    }
    // 3. Query
    return _root->first(_path);
  }

  operator Node<void> *() const { return resolve(); }
  Node<void> *operator->() const { return resolve(); }
  Node<void> &operator*() const {
    Node<void> *n = resolve();
    return *n;
  }

  explicit operator bool() const { return resolve() != nullptr; }
  bool operator==(decltype(nullptr)) const { return resolve() == nullptr; }
  bool operator!=(decltype(nullptr)) const { return resolve() != nullptr; }
  bool operator==(const Node<void> *o) const { return resolve() == o; }
  bool operator!=(const Node<void> *o) const { return resolve() != o; }

  template <typename T>
  T as() const {
    Node<void> *n = resolve();
    if (!n) return T{};
    return n->as<T>();
  }

  void remove() {
    if (!_root) return;
    _root->remove(_path);
  }

  template <typename U>
  NodeProxy &operator=(U &&val) {
    using CleanU = typename Xi::Decay<U>::Type;
    if constexpr (std::is_same_v<CleanU, NodeProxy>) {
      Node<void> *resolved = val.resolve();
      if (resolved) {
        setNode(resolved->clone());
      }
    } else if constexpr (std::is_base_of_v<Node<void>, std::remove_pointer_t<CleanU>>) {
      if constexpr (std::is_pointer_v<CleanU>) {
        setNode(val);
      } else {
        setNode(val.clone());
      }
    } else if constexpr (std::is_same_v<CleanU, const char *> || std::is_same_v<CleanU, char *>) {
      setValue<String>(String(val));
    } else {
      setValue<CleanU>(std::forward<U>(val));
    }
    return *this;
  }

  NodeProxy &operator=(const NodeProxy &other) {
    Node<void> *resolved = other.resolve();
    if (resolved) {
      setNode(resolved->clone());
    }
    return *this;
  }

  void setNode(Node<void> *node) {
    if (!node) return;
    if (checkVirtualSetter(node)) return;

    String leafName;
    Node<void> *targetParent = getOrCreateParent(leafName);
    if (!targetParent) return;

    // Find all exact matching children and delete them
    targetParent->remove(leafName);

    node->name = leafName;
    targetParent->add(node);
  }

  template <typename V>
  void setValue(V &&v) {
    Node<typename Xi::Decay<V>::Type> *newNode =
        new Node<typename Xi::Decay<V>::Type>(std::forward<V>(v));
    setNode(newNode);
  }
};

inline NodeProxy Node<void>::operator[](const String &key) {
  return NodeProxy(this, key);
}

inline NodeProxy Node<void>::operator[](const char *key) {
  return NodeProxy(this, String(key));
}

inline const NodeProxy Node<void>::operator[](const String &key) const {
  return NodeProxy(const_cast<Node<void> *>(this), key);
}

inline const NodeProxy Node<void>::operator[](const char *key) const {
  return NodeProxy(const_cast<Node<void> *>(this), String(key));
}

// -------------------------------------------------------------------------
// Selector & Query Implementations
// -------------------------------------------------------------------------

inline bool SelectorSegment::matchesNameAndTags(const Node<void> *item) const {
  if (!item) return false;
  if (isDoubleStar) return true;
  if (!name.isEmpty() && name != "*") {
    if (item->name != name) return false;
  }
  for (usz i = 0; i < tags.size(); ++i) {
    if (!item->hasTag(tags[i])) return false;
  }
  return true;
}

inline Array<SelectorSegment> Node<void>::parse_path(const String &queryStr) {
  Array<SelectorSegment> segments;
  if (queryStr.length() == 0) return segments;

  Array<String> parts = queryStr.split("/");
  for (usz i = 0; i < parts.size(); ++i) {
    String part = parts[i].trim();
    if (part.isEmpty()) continue;

    SelectorSegment seg;
    // 1. Check for ## indexing (##0, ##1, ##first, ##last)
    long long idxPos = part.indexOf("##");
    if (idxPos != -1) {
      long long nextHash = part.indexOf('#', idxPos + 2);
      long long nextDot = part.indexOf('.', idxPos + 2);
      long long endIdx = static_cast<long long>(part.length());
      if (nextHash != -1 && nextHash < endIdx) endIdx = nextHash;
      if (nextDot != -1 && nextDot < endIdx) endIdx = nextDot;

      String idxStr = part.substring(idxPos + 2, endIdx).trim();
      if (idxStr == "first") {
        seg.index = 0;
      } else if (idxStr == "last") {
        seg.index = -1;
      } else {
        seg.index = parseInt(idxStr);
      }
      part = part.substring(0, idxPos) + part.substring(endIdx);
    }

    // 2. Check for **
    if (part == "**" || part.startsWith("**#") || part.startsWith("**.")) {
      seg.isDoubleStar = true;
      seg.name = "**";
      part = part.substring(2);
    }

    // 3. Extract name and tags (#tag or .tag)
    String curName;
    usz pos = 0;
    while (pos < part.length() && part.charAt(pos) != '#' && part.charAt(pos) != '.') {
      curName += part.charAt(pos++);
    }
    if (!seg.isDoubleStar) {
      seg.name = curName;
    }

    while (pos < part.length()) {
      char delimiter = part.charAt(pos++);
      (void)delimiter;
      String tag;
      while (pos < part.length() && part.charAt(pos) != '#' && part.charAt(pos) != '.') {
        tag += part.charAt(pos++);
      }
      tag = tag.trim();
      if (!tag.isEmpty()) {
        seg.tags.push(tag);
      }
    }

    if (seg.name.isEmpty() && (seg.tags.size() > 0 || seg.index != -2)) {
      seg.name = "*";
    }

    segments.push(seg);
  }
  return segments;
}

inline void Node<void>::collect_all_descendants(Node<void> *curr,
                                                Array<Node<void> *> &out) {
  if (!curr) return;
  for (usz i = 0; i < curr->children.size(); ++i) {
    Node<void> *c = curr->children[i];
    if (c) {
      if (!out.includes(c)) out.push(c);
      collect_all_descendants(c, out);
    }
  }
}

inline void Node<void>::query_step(Node<void> *curr, usz segIdx,
                                   const Array<SelectorSegment> &segments,
                                   Array<Node<void> *> &out) {
  if (!curr || segIdx >= segments.size()) return;
  const SelectorSegment &seg = segments[segIdx];

  if (seg.isDoubleStar) {
    if (segIdx + 1 == segments.size()) {
      Array<Node<void> *> allDesc;
      collect_all_descendants(curr, allDesc);
      Array<Node<void> *> matched;
      for (usz i = 0; i < allDesc.size(); ++i) {
        if (seg.matchesNameAndTags(allDesc[i])) matched.push(allDesc[i]);
      }
      if (seg.index == -1) {
        if (matched.size() > 0 && !out.includes(matched[matched.size() - 1]))
          out.push(matched[matched.size() - 1]);
      } else if (seg.index >= 0) {
        if (static_cast<usz>(seg.index) < matched.size() && !out.includes(matched[static_cast<usz>(seg.index)]))
          out.push(matched[static_cast<usz>(seg.index)]);
      } else {
        for (usz i = 0; i < matched.size(); ++i) {
          if (!out.includes(matched[i])) out.push(matched[i]);
        }
      }
      return;
    }

    // ** followed by more segments
    for (usz i = 0; i < curr->children.size(); ++i) {
      Node<void> *c = curr->children[i];
      if (!c) continue;
      query_step(c, segIdx + 1, segments, out);
      query_step(c, segIdx, segments, out);
    }
    return;
  }

  // Not double star: evaluate seg against curr's children
  Array<Node<void> *> matched;
  for (usz i = 0; i < curr->children.size(); ++i) {
    Node<void> *c = curr->children[i];
    if (c && seg.matchesNameAndTags(c)) {
      matched.push(c);
    }
  }

  Array<Node<void> *> filtered;
  if (seg.index == -1) {
    if (matched.size() > 0) {
      filtered.push(matched[matched.size() - 1]);
    }
  } else if (seg.index >= 0) {
    if (static_cast<usz>(seg.index) < matched.size()) {
      filtered.push(matched[static_cast<usz>(seg.index)]);
    }
  } else {
    filtered = matched;
  }

  if (segIdx + 1 == segments.size()) {
    for (usz i = 0; i < filtered.size(); ++i) {
      if (!out.includes(filtered[i])) {
        out.push(filtered[i]);
      }
    }
  } else {
    for (usz i = 0; i < filtered.size(); ++i) {
      query_step(filtered[i], segIdx + 1, segments, out);
    }
  }
}

template <typename... Ts>
inline Array<Node<void> *> Node<void>::query(const String &selector) {
  Array<Node<void> *> results;
  Array<SelectorSegment> segments = parse_path(selector);
  if (segments.size() == 0) return results;

  // Single segment matching self (only if exact name match without child-index filter)
  if (segments.size() == 1 &&
      !segments[0].name.isEmpty() &&
      segments[0].name != "*" &&
      segments[0].name == this->name &&
      segments[0].index == -2 &&
      segments[0].matchesNameAndTags(this)) {
    results.push(this);
  }

  query_step(this, 0, segments, results);

  // Filter by types Ts... if provided
  if constexpr (sizeof...(Ts) > 0) {
    Array<Node<void> *> filtered;
    for (usz i = 0; i < results.size(); ++i) {
      bool ok = ((dynamic_cast<Ts *>(results[i]) != nullptr) && ...);
      if (ok) filtered.push(results[i]);
    }
    return filtered;
  }

  return results;
}

inline void Node<void>::remove(const String &selector) {
  if (selector.indexOf('/') == -1 && selector.indexOf('*') == -1 && selector.indexOf('#') == -1) {
    for (long long i = static_cast<long long>(children.size()) - 1; i >= 0; --i) {
      if (children[i] && children[i]->name == selector) {
        Node<void> *target = children[i];
        children.splice(i, 1);
        target->parent = nullptr;
        delete target;
      }
    }
    return;
  }

  Array<Node<void> *> toDelete = query(selector);
  for (usz i = 0; i < toDelete.size(); ++i) {
    delete toDelete[i];
  }
}

inline Array<Node<void> *> Node<void>::flatten() {
  Array<Node<void> *> out;
  collect_all_descendants(this, out);
  return out;
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
  return root->first<Ts...>(selector);
}

} // namespace Xi

#endif // XI_CORE_TREE_HPP
