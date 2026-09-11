/**
 * @file Yaml.hpp
 * @brief High-performance YAML and JSON parser and emitter for the Xi framework.
 */

#ifndef XI_DATA_YAML_HPP
#define XI_DATA_YAML_HPP

#include "../Xi/Tree.hpp"

namespace Data {

using namespace Xi;

/**
 * @class YAML
 * @brief Provides static methods for YAML and JSON parsing and serialization.
 */
class XI_EXPORT YAML {
public:
  /**
   * @brief Parses a YAML or JSON string into a Node<void>.
   * @param yamlString The input string.
   * @param outRoot The root Node<void> to populate.
   * @return True if successful, false otherwise.
   */
  static bool parse(const String &yamlString, Node<void> &outRoot);

  /**
   * @brief Hydrates a tree by checking for _type tags and instantiating custom
   * classes. Internal recursive helper.
   */
  template <typename BaseT> static void hydrateRecursive(Node<void> *item) {
    if (!item)
      return;

    for (usz i = 0; i < item->size(); ++i) {
      Node<void> *child = (*item)[i];
      if (child) {
        Node<void> *rawType = child->get("_type");
        if (rawType) {
          String typeName;
          if (auto s = dynamic_cast<Node<String> *>(rawType))
            typeName = s->value;

          if (typeName == demangle_type_name<BaseT>()) {
            BaseT *obj = new BaseT();
            obj->name = child->name;
            obj->tags = child->tags;

            for (usz k = 0; k < child->size(); ++k) {
              if ((*child)[k])
                obj->add((*child)[k]->clone());
            }

            item->children[i] = obj;
            obj->parent = item;
            delete child;
            child = obj;

            if constexpr (HasParseHydrate<BaseT>::value) {
              obj->parseHydrate();
            }
          }
        }
        hydrateRecursive<BaseT>(child);
      }
    }
  }

  /**
   * @brief Serializes a Node<void> into a YAML string.
   * @param root The root node.
   * @param indentation Indentation size in spaces.
   * @return The YAML string.
   */
  static String toYAML(const Node<void> &root, int indentation = 2);

  /**
   * @brief Serializes a Node<void> into a JSON string.
   * @param root The root node.
   * @param indentation Indentation size in spaces.
   * @return The JSON string.
   */
  static String toJSON(const Node<void> &root, int indentation = 4);
};

/**
 * @brief Helper function for parsing YAML or JSON.
 */
inline bool parseYAML(const String &yamlString, Node<void> &tree) {
  return YAML::parse(yamlString, tree);
}

/**
 * @brief Template helper for parsing and hydrating specific types.
 */
template <typename T>
inline bool parseYAML(const String &yamlString, Node<void> &tree) {
  if (YAML::parse(yamlString, tree)) {
    YAML::hydrateRecursive<T>(&tree);
    return true;
  }
  return false;
}

/**
 * @brief Helper function for parsing JSON (alias for YAML parser).
 */
inline bool parseJSON(const String &jsonString, Node<void> &tree) {
  return YAML::parse(jsonString, tree);
}

/**
 * @brief Template helper for parsing and hydrating specific types from JSON.
 */
template <typename T>
inline bool parseJSON(const String &jsonString, Node<void> &tree) {
  if (YAML::parse(jsonString, tree)) {
    YAML::hydrateRecursive<T>(&tree);
    return true;
  }
  return false;
}

/**
 * @brief Helper function for serializing to YAML.
 */
inline String toYAML(const Node<void> &tree, int indentation = 2) {
  return YAML::toYAML(tree, indentation);
}

/**
 * @brief Helper function for serializing to JSON.
 */
inline String toJSON(const Node<void> &tree, int indentation = 4) {
  return YAML::toJSON(tree, indentation);
}

} // namespace Data

#endif // XI_DATA_YAML_HPP
