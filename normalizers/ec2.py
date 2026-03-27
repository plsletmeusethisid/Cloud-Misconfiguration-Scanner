from models.resource import create_resource


def normalize_instance(raw_instance):
    resource = create_resource(
        resource_id=raw_instance["InstanceId"],
        resource_type="compute_instance"
    )

    resource["config"] = {
        "public_ip": "PublicIpAddress" in raw_instance
    }

    for sg in raw_instance.get("SecurityGroups", []):
        resource["relationships"].append({
            "type": "uses_security_group",
            "target_id": sg["GroupId"]
        })

    if "IamInstanceProfile" in raw_instance:
        role_arn = raw_instance["IamInstanceProfile"]["Arn"]
        role_name = role_arn.split("/")[-1]

        resource["relationships"].append({
            "type": "assumes_role",
            "target_id": role_name
        })

    return resource
