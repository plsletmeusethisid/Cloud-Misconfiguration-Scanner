from models.resource import create_resource


def extract_policies(policy_doc):
    policies = []

    for stmt in policy_doc.get("Statement", []):
        policies.append({
            "effect": stmt.get("Effect"),
            "action": stmt.get("Action"),
            "resource": stmt.get("Resource")
        })

    return policies


def normalize_iam_role(role_name, policy_doc):
    resource = create_resource(
        resource_id=role_name,
        resource_type="iam_role"
    )

    policies = extract_policies(policy_doc)

    resource["config"] = {
        "policies": policies,
        "is_admin": any(
            p["action"] == "*" and p["resource"] == "*"
            for p in policies
        )
    }

    return resource
