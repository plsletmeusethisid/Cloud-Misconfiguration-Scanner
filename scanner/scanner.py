from policy_engine.engine import run_policy


def scan(resources, policies):
    findings = []

    for policy in policies:
        for r in resources.values():
            try:
                if run_policy(policy["rule"], r):
                    findings.append({
                        "policy_name": policy["name"],
                        "severity": policy["severity"],
                        "resource_id": r["id"],
                        "resource_type": r["type"]
                    })
            except Exception:
                continue

    return findings
