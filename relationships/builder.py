def build_reverse_relationships(resource_map):
    for resource in list(resource_map.values()):
        for rel in resource.get("relationships", []):
            target_id = rel["target_id"]

            if target_id in resource_map:
                resource_map[target_id]["relationships"].append({
                    "type": f"reverse_{rel['type']}",
                    "target_id": resource["id"],
                    "metadata": rel.get("metadata", {})
                })
