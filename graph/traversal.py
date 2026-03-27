def traverse(resource_map, start_id, max_depth=5):
    """
    Walk the resource graph from start_id up to max_depth hops.

    Yields every complete path found as a list of dicts:
        [
            {"resource_id": "internet",  "via_relationship": None},
            {"resource_id": "sg-123",    "via_relationship": "allows_ingress"},
            {"resource_id": "i-abc",     "via_relationship": "reverse_uses_security_group"},
            {"resource_id": "admin-role","via_relationship": "assumes_role"},
        ]

    The first hop always has via_relationship=None (it's the origin).
    """
    if start_id not in resource_map:
        return

    start_node = {"resource_id": start_id, "via_relationship": None}

    stack = [(start_node, [start_node], 0)]

    while stack:
        current_node, current_path, depth = stack.pop()

        yield list(current_path)

        if depth >= max_depth:
            continue

        resource = resource_map.get(current_node["resource_id"])
        if not resource:
            continue

        for rel in resource.get("relationships", []):
            target_id = rel["target_id"]
            rel_type = rel["type"]

            next_node = {"resource_id": target_id, "via_relationship": rel_type}
            stack.append((next_node, current_path + [next_node], depth + 1))
