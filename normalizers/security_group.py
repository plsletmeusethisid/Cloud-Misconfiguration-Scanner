from models.resource import create_resource


def extract_inbound_rules(ip_permissions):
    rules = []

    for perm in ip_permissions:
        protocol = perm.get("IpProtocol")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        for ip_range in perm.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")

            rules.append({
                "port": from_port,
                "to_port": to_port,
                "protocol": protocol,
                "cidr": cidr,
                "is_public": cidr == "0.0.0.0/0"
            })

    return rules


def normalize_security_group(raw_sg):
    resource = create_resource(
        resource_id=raw_sg["GroupId"],
        resource_type="security_group"
    )

    inbound_rules = extract_inbound_rules(raw_sg.get("IpPermissions", []))

    resource["config"] = {
        "inbound_rules": inbound_rules
    }

    for rule in inbound_rules:
        if rule["is_public"]:
            resource["relationships"].append({
                "type": "allows_ingress",
                "target_id": "internet",
                "metadata": {
                    "port": rule["port"],
                    "protocol": rule["protocol"]
                }
            })

    return resource
