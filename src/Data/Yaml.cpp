#include "../../include/Data/Yaml.hpp"
#include "../../include/Xi/Map.hpp"
#include "../../include/Xi/Xi.hpp"

namespace Data {

using namespace Xi;

static inline bool isSpace(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static inline void emitIdent(String &str, int count) {
  for (int i = 0; i < count; i++)
    str += " ";
}

struct YamlParser {
  const String &input;
  usz i = 0;
  int currentIndent = 0;
  bool isNewLine = true;
  Map<String, Node<void> *> anchors;

  YamlParser(const String &s) : input(s) {}

  void skipSpace() {
    while (i < input.length()) {
      char c = input.charAt(i);
      if (c == ' ') {
        if (isNewLine)
          currentIndent++;
        i++;
      } else if (c == '\t') {
        if (isNewLine)
          currentIndent += 4;
        i++;
      } else if (c == '\r' || c == '\n') {
        isNewLine = true;
        currentIndent = 0;
        i++;
      } else {
        isNewLine = false;
        break;
      }
    }
  }

  void skipComments(Node<void> *node = nullptr) {
    while (i < input.length()) {
      skipSpace();
      if (i + 1 < input.length()) {
        char c1 = input.charAt(i);
        char c2 = input.charAt(i + 1);
        if (c1 == '#') {
          i++;
          String comm;
          while (i < input.length() && input.charAt(i) != '\n') {
            comm += input.charAt(i++);
          }
          if (node) {
            auto *c = new Node<String>(comm.trim());
            c->name = "_comment";
            node->add(c);
          }
          isNewLine = true;
          currentIndent = 0;
        } else if (c1 == '/' && c2 == '/' && (i == 0 || input.charAt(i - 1) == ' ' || input.charAt(i - 1) == '\t' || input.charAt(i - 1) == '\n')) {
          i += 2;
          String comm;
          while (i < input.length() && input.charAt(i) != '\n') {
            comm += input.charAt(i++);
          }
          if (node) {
            auto *c = new Node<String>(comm.trim());
            c->name = "_comment";
            node->add(c);
          }
          isNewLine = true;
          currentIndent = 0;
        } else if (c1 == '/' && c2 == '*' && (i == 0 || input.charAt(i - 1) == ' ' || input.charAt(i - 1) == '\t' || input.charAt(i - 1) == '\n')) {
          i += 2;
          String comm;
          while (i + 1 < input.length() &&
                 !(input.charAt(i) == '*' && input.charAt(i + 1) == '/')) {
            comm += input.charAt(i++);
          }
          i += 2;
          if (node) {
            auto *c = new Node<String>(comm.trim());
            c->name = "_comment";
            node->add(c);
          }
        } else {
          break;
        }
      } else if (i < input.length() && input.charAt(i) == '#') {
        i++;
        break;
      } else {
        break;
      }
    }
  }

  String parseString() {
    String res;
    char quote = input.charAt(i);
    bool isQuoted = (quote == '\"' || quote == '\x27');
    if (isQuoted) {
      i++;
      while (i < input.length()) {
        char c = input.charAt(i);
        if (c == quote) {
          i++;
          break;
        }
        if (c == '\\' && i + 1 < input.length()) {
          i++;
          char esc = input.charAt(i);
          if (esc == 'n')
            res += '\n';
          else if (esc == 'r')
            res += '\r';
          else if (esc == 't')
            res += '\t';
          else
            res += esc;
        } else {
          res += c;
        }
        i++;
      }
    } else {
      while (i < input.length()) {
        char c = input.charAt(i);
        if (c == ':' || c == ',' || c == ']' || c == '}' || c == '#' ||
            c == '\n' || c == '\r')
          break;
        res += c;
        i++;
      }
      res = res.trim();
    }
    return res;
  }

  Node<void> *parseValue(int parentIndent, Node<void> *parentBranch = nullptr) {
    while (true) {
      skipComments(parentBranch);
      if (i >= input.length())
        return nullptr;

      // Skip Directives (%YAML, %TAG) at root level
      if (currentIndent == 0 && input.charAt(i) == '%' &&
          (input.indexOf("%YAML", i) == i || input.indexOf("%TAG", i) == i)) {
        while (i < input.length() && input.charAt(i) != '\n')
          i++;
        isNewLine = true;
        currentIndent = 0;
        continue;
      }

      // Skip Document Separators (---)
      if (input.charAt(i) == '-' && i + 2 < input.length() &&
          input.charAt(i + 1) == '-' && input.charAt(i + 2) == '-') {
        i += 3;
        while (i < input.length() && input.charAt(i) != '\n')
          i++;
        isNewLine = true;
        currentIndent = 0;
        continue;
      }
      break;
    }

    if (i >= input.length())
      return nullptr;

    // Check for Anchors & Aliases
    if (input.charAt(i) == '&') {
      i++;
      String anchorName;
      while (i < input.length() && !isSpace(input.charAt(i)) &&
             input.charAt(i) != '\n') {
        anchorName += input.charAt(i++);
      }
      Node<void> *val = parseValue(parentIndent, parentBranch);
      if (val)
        anchors.put(anchorName, val);
      return val;
    }
    if (input.charAt(i) == '*') {
      i++;
      String aliasName;
      while (i < input.length() && !isSpace(input.charAt(i)) &&
             input.charAt(i) != '\n') {
        aliasName += input.charAt(i++);
      }
      Node<void> **ref = anchors.get(aliasName);
      if (ref && *ref)
        return (*ref)->clone();
      return nullptr;
    }

    int blockIndent = currentIndent;

    // Flow Style Sequence
    if (input.charAt(i) == '[') {
      i++;
      auto *arr = new Node<void>();
      while (i < input.length()) {
        skipComments(arr);
        if (input.charAt(i) == ']') {
          i++;
          break;
        }
        Node<void> *val = parseValue(blockIndent, arr);
        if (val)
          arr->add(val);
        skipSpace();
        if (input.charAt(i) == ',') {
          i++;
        }
      }
      return arr;
    }

    // Flow Style Mapping
    if (input.charAt(i) == '{') {
      i++;
      auto *mapNode = new Node<void>();
      while (i < input.length()) {
        skipComments(mapNode);
        if (input.charAt(i) == '}') {
          i++;
          break;
        }
        String k = parseString();
        skipSpace();
        if (input.charAt(i) == ':') {
          i++;
        }
        Node<void> *val = parseValue(blockIndent, mapNode);
        if (val) {
          val->name = k;
          mapNode->add(val);
        }
        skipSpace();
        if (input.charAt(i) == ',') {
          i++;
        }
      }
      return mapNode;
    }

    // Block Sequence
    if (input.charAt(i) == '-' && (i + 1 < input.length() && isSpace(input.charAt(i + 1)))) {
      auto *arr = new Node<void>();
      int seqIndent = currentIndent;
      while (i < input.length()) {
        skipComments(arr);
        if (currentIndent < seqIndent)
          break;
        if (input.charAt(i) != '-')
          break;
        i++; // skip '-'
        skipSpace();
        Node<void> *val = parseValue(seqIndent + 1, arr);
        if (val)
          arr->add(val);
        skipComments(arr);
      }
      return arr;
    }

    // Look ahead to check if this is a key-value mapping
    bool isKey = false;
    usz peek = i;
    if (peek < input.length() && (input.charAt(peek) == '\"' || input.charAt(peek) == '\x27')) {
      char q = input.charAt(peek++);
      while (peek < input.length()) {
        if (input.charAt(peek) == '\\' && peek + 1 < input.length()) {
          peek += 2;
          continue;
        }
        if (input.charAt(peek) == q) {
          peek++;
          break;
        }
        peek++;
      }
      while (peek < input.length() && isSpace(input.charAt(peek))) peek++;
      if (peek < input.length() && input.charAt(peek) == ':' &&
          (peek + 1 >= input.length() || isSpace(input.charAt(peek + 1)) || input.charAt(peek + 1) == '\n' || input.charAt(peek + 1) == '\r')) {
        isKey = true;
      }
    } else {
      while (peek < input.length()) {
        char cp = input.charAt(peek);
        if (cp == '\n' || cp == '\r')
          break;
        if (cp == ':' && (peek + 1 >= input.length() || isSpace(input.charAt(peek + 1)) || input.charAt(peek + 1) == '\n' || input.charAt(peek + 1) == '\r')) {
          isKey = true;
          break;
        }
        peek++;
      }
    }

    if (isKey) {
      auto *branch = new Node<void>();
      while (i < input.length()) {
        skipComments(branch);
        if (currentIndent < blockIndent)
          break;
        if (i >= input.length())
          break;

        if (input.charAt(i) == '-' && (i + 1 >= input.length() || isSpace(input.charAt(i + 1))))
          break;

        String k;
        if (input.charAt(i) == '\"' || input.charAt(i) == '\x27') {
          k = parseString();
          skipSpace();
          if (i < input.length() && input.charAt(i) == ':') i++;
        } else {
          while (i < input.length()) {
            char ck = input.charAt(i);
            if (ck == '\n' || ck == '\r') break;
            if (ck == ':' && (i + 1 >= input.length() || isSpace(input.charAt(i + 1)) || input.charAt(i + 1) == '\n' || input.charAt(i + 1) == '\r')) {
              i++;
              break;
            }
            k += ck;
            i++;
          }
        }
        k = k.trim();
        if (k.isEmpty()) break;

        Node<void> *v = parseValue(blockIndent, branch);
        if (v) {
          v->name = k;
          branch->add(v);
        }

        skipComments(branch);
        if (currentIndent < blockIndent) break;
      }
      return branch;
    }

    // Scalar
    String s = parseString();
    if (s == "true")
      return new Node<bool>(true);
    if (s == "false")
      return new Node<bool>(false);
    if (s == "null" || s == "~") {
      auto *n = new Node<void>();
      n->isNull = true;
      return n;
    }

    bool isNum = true;
    int dotCount = 0;
    for (usz k = 0; k < s.length(); ++k) {
      if (s.charAt(k) == '.')
        dotCount++;
      else if (s.charAt(k) < '0' || s.charAt(k) > '9') {
        if (k != 0 || s.charAt(k) != '-')
          isNum = false;
      }
    }
    if (isNum && s.length() > 0 && s != "-" && dotCount <= 1) {
      if (dotCount == 1)
        return new Node<f64>(s.toDouble());
      return new Node<long long>(s.toInt());
    }
    return new Node<String>(s);
  }
};

bool YAML::parse(const String &yaml, Node<void> &outRoot) {
  YamlParser p(yaml);
  Node<void> *root = &outRoot;
  if (!root)
    return false;

  while (p.i < yaml.length()) {
    Node<void> *res = p.parseValue(-1, root);
    if (!res)
      break;

    if (res) {
      if (!res->hasValue()) {
        for (usz i = 0; i < res->size(); ++i) {
          if ((*res)[i])
            root->add((*res)[i]->clone());
        }
        delete res;
      } else {
        root->add(res);
      }
    }
    p.skipSpace();
  }
  return true;
}

static String emitValue(const Node<void> *node, int indentLevel, int indentSize, bool firstLineNoIndent = false) {
  // 1. Handles isNull before children and value
  if (!node || node->isNull)
    return "null";

  // 2. If there is a value, then children arent checked...
  if (node->hasValue()) {
    if (auto s = dynamic_cast<const Node<String> *>(node))
      return s->value;
    if (auto i = dynamic_cast<const Node<long long> *>(node))
      return String(i->value);
    if (auto b = dynamic_cast<const Node<bool> *>(node))
      return b->value ? "true" : "false";
    if (auto f = dynamic_cast<const Node<f64> *>(node))
      return String(f->value);
    return "null";
  }

  // 3. Array (children all without name)
  if (node->isArray()) {
    if (node->size() == 0)
      return "[]";
    String res;
    bool first = true;
    for (usz i = 0; i < node->size(); ++i) {
      Node<void> *child = (*node)[i];
      if (!child) continue;
      if (child->name == "_comment") {
        if (!(first && firstLineNoIndent)) {
          emitIdent(res, (indentLevel) * indentSize);
        }
        if (auto comm = dynamic_cast<const Node<String> *>(child))
          res += "# " + comm->value + "\n";
        continue;
      }
      if (!(first && firstLineNoIndent)) {
        emitIdent(res, (indentLevel) * indentSize);
      }
      first = false;
      res += "- " + emitValue(child, indentLevel + 1, indentSize, true) + "\n";
    }
    return res;
  }

  // 4. Object (children with names)
  if (node->size() == 0)
    return "{}";
  String res;
  for (usz i = 0; i < node->size(); ++i) {
    Node<void> *child = (*node)[i];
    if (!child) continue;
    if (child->name == "_comment") {
      if (!(i == 0 && firstLineNoIndent)) {
        emitIdent(res, (indentLevel) * indentSize);
      }
      if (auto comm = dynamic_cast<const Node<String> *>(child))
        res += "# " + comm->value + "\n";
      continue;
    }
    if (!(i == 0 && firstLineNoIndent)) {
      emitIdent(res, (indentLevel) * indentSize);
    }
    res += child->name + ":";
    if (!child->hasValue() && child->size() > 0) {
      res += "\n";
      res += emitValue(child, indentLevel + 1, indentSize);
    } else {
      res += " " + emitValue(child, indentLevel, indentSize, true) + "\n";
    }
  }
  return res;
}

String YAML::toYAML(const Node<void> &root, int indent) {
  return emitValue(&root, 0, indent);
}

String YAML::toJSON(const Node<void> &root, int indent) {
  return toYAML(root, indent);
}

} // namespace Data
