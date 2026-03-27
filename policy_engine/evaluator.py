def get_field(obj, path):
    parts = path.split(".")
    value = obj

    for p in parts:
        if not isinstance(value, dict):
            return None
        value = value.get(p)
        if value is None:
            return None

    return value


def evaluate(node, resource):
    t = node["type"]

    if t == "EQ":
        field = node["field"]

        if field.startswith("resource."):
            field = field.split(".", 1)[1]
            value = resource.get(field)
        else:
            value = get_field(resource, field)

        return value == node["value"]

    if t == "AND":
        return evaluate(node["left"], resource) and evaluate(node["right"], resource)

    if t == "OR":
        return evaluate(node["left"], resource) or evaluate(node["right"], resource)

    if t == "NOT":
        return not evaluate(node["expr"], resource)

    if t == "EXISTS":
        collection = get_field(resource, node["collection"])
        if not isinstance(collection, list):
            return False

        return any(evaluate(node["condition"], item) for item in collection)

    raise Exception(f"Unknown node type: {t}")
