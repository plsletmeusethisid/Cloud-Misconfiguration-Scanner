from pipeline import build_resources
from scanner.policies import POLICIES
from scanner.scanner import scan
from scanner.attack_paths import detect_attack_paths
from scanner.reporter import print_report

raw_data = {
    "security_groups": [
        {
            "GroupId": "sg-123",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        }
    ],
    "instances": [
        {
            "Instances": [
                {
                    "InstanceId": "i-abc",
                    "SecurityGroups": [{"GroupId": "sg-123"}],
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::123456789012:instance-profile/admin-role"
                    }
                }
            ]
        }
    ],
    "buckets": [
        {
            "Name": "public-bucket",
            "Policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*"
                    }
                ]
            },
            "Encryption": False
        }
    ],
    "roles": [
        {
            "RoleName": "admin-role",
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
        }
    ]
}

resource_map = build_resources(raw_data)

# --- policy findings ---
policy_findings = scan(resource_map, POLICIES)

# --- attack path findings ---
path_findings = detect_attack_paths(resource_map, max_depth=5)

# --- merge and report ---
all_findings = path_findings + policy_findings
print_report(all_findings)
