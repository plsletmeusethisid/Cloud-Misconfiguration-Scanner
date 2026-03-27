from models.resource import create_resource


def is_bucket_public(policy):
    if not policy:
        return False

    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
            return True

    return False


def normalize_s3_bucket(bucket_name, policy=None, encryption=False):
    resource = create_resource(
        resource_id=bucket_name,
        resource_type="s3_bucket"
    )

    is_public = is_bucket_public(policy)

    resource["config"] = {
        "public": is_public,
        "encryption": encryption
    }

    if is_public:
        resource["relationships"].append({
            "type": "exposed_to_internet",
            "target_id": "internet",
            "metadata": {}
        })

    return resource
