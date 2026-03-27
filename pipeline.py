from normalizers.security_group import normalize_security_group
from normalizers.ec2 import normalize_instance
from normalizers.s3 import normalize_s3_bucket
from normalizers.iam import normalize_iam_role
from relationships.builder import build_reverse_relationships


def build_resources(raw_data):
    resources = []

    for sg in raw_data.get("security_groups", []):
        resources.append(normalize_security_group(sg))

    for reservation in raw_data.get("instances", []):
        for instance in reservation.get("Instances", []):
            resources.append(normalize_instance(instance))

    for bucket in raw_data.get("buckets", []):
        resources.append(
            normalize_s3_bucket(
                bucket_name=bucket["Name"],
                policy=bucket.get("Policy"),
                encryption=bucket.get("Encryption", False)
            )
        )

    for role in raw_data.get("roles", []):
        resources.append(
            normalize_iam_role(
                role_name=role["RoleName"],
                policy_doc=role.get("PolicyDocument", {})
            )
        )

    # Internet node
    resources.append({
        "id": "internet",
        "type": "external",
        "provider": "aws",
        "region": None,
        "config": {},
        "relationships": []
    })

    resource_map = {r["id"]: r for r in resources}

    build_reverse_relationships(resource_map)

    return resource_map
