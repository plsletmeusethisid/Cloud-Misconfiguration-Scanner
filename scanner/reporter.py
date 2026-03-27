SEVERITY_ORDER = ["CRITICAL_PATH", "CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _sort_findings(findings):
    def rank(f):
        sev = f.get("severity", "LOW")
        try:
            return SEVERITY_ORDER.index(sev)
        except ValueError:
            return len(SEVERITY_ORDER)
    return sorted(findings, key=rank)


def _print_chain(chain):
    for i, hop in enumerate(chain):
        rid = hop["resource_id"]
        via = hop["via_relationship"]
        if i == 0:
            print(f"    {'START':>25}  →  {rid}")
        else:
            print(f"    {via:>25}  →  {rid}")


def print_report(findings):
    if not findings:
        print("No issues found ✅")
        return

    sorted_findings = _sort_findings(findings)

    attack_paths = [f for f in sorted_findings if f.get("severity") == "CRITICAL_PATH"]
    regular      = [f for f in sorted_findings if f.get("severity") != "CRITICAL_PATH"]

    if attack_paths:
        print("=" * 60)
        print("  ⛓  ATTACK PATHS DETECTED")
        print("=" * 60)
        for f in attack_paths:
            print(f"\n[{f['severity']}] {f['policy_name']}")
            print(f"Entry Point : {f['resource_id']} ({f['resource_type']})")
            print(f"Risk        : {f['description']}")
            print("Chain:")
            _print_chain(f["chain"])
            print("-" * 60)

    if regular:
        print("\n" + "=" * 60)
        print("  🔍  POLICY FINDINGS")
        print("=" * 60)
        for f in regular:
            print(f"\n[{f['severity']}] {f['policy_name']}")
            print(f"Resource: {f['resource_id']} ({f['resource_type']})")
            print("-" * 60)
