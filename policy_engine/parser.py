def parse(tokens):
    if not tokens:
        raise Exception("Empty expression")

    if "OR" in tokens:
        idx = tokens.index("OR")
        return {
            "type": "OR",
            "left": parse(tokens[:idx]),
            "right": parse(tokens[idx + 1:])
        }

    if "AND" in tokens:
        idx = tokens.index("AND")
        return {
            "type": "AND",
            "left": parse(tokens[:idx]),
            "right": parse(tokens[idx + 1:])
        }

    if tokens[0] == "NOT":
        return {"type": "NOT", "expr": parse(tokens[1:])}

    if tokens[0] == "EXISTS":
        collection = tokens[1]
        where_idx = tokens.index("WHERE")
        return {
            "type": "EXISTS",
            "collection": collection,
            "condition": parse(tokens[where_idx + 1:])
        }

    if "==" in tokens:
        idx = tokens.index("==")
        field = tokens[idx - 1]
        value = tokens[idx + 1]

        if value == "true":
            value = True
        elif value == "false":
            value = False
        elif value.startswith('"'):
            value = value.strip('"')
        elif value.isdigit():
            value = int(value)

        return {"type": "EQ", "field": field, "value": value}

    raise Exception(f"Invalid expression: {tokens}")
