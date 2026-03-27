from graph.traversal import traverse


# ---------------------------------------------------------------------------
# Attack path definitions
# Each definition is a list of "hop matchers".
# A hop matcher is a dict with any subset of these keys:
#   - resource_type : the resource's type field must match
#   - resource_id   : the resource's id must match exactly
#   - via           : the relationship type used to arrive at this hop
#                     (None means "entry point, no incoming edge required")
#
# A path matches a definition if every consecutive hop in the path
# satisfies the corresponding matcher in order.
# ---------------------------------------------------------------------------

ATTACK_PATH_DEFINITIONS = [
    {
        "name": "Internet → Open Port → Compute → Admin IAM Role",
        "severity": "CRITICAL_PATH",
        "description": (
            "An internet-reachable entry point leads through a permissive "
            "security group into a compute instance that assumes an admin IAM role. "
            "This represents a full privilege escalation path from the public internet."
        ),
        "chain": [
            {"resource_id": "internet",           "via": None},
            {"resource_type": "security_group",   "via": "allows_ingress"},
            {"resource_type": "compute_instance", "via": "reverse_uses_security_group"},
            {"resource_type": "iam_role",         "via": "assumes_role"},
        ],
    },
    {
        "name": "Internet → Public S3 Bucket (Unencrypted)",
        "severity": "CRITICAL_PATH",
        "description": (
            "A publicly exposed S3 bucket with no encryption is directly "
            "reachable from the internet, risking data exfiltration."
        ),
        "chain": [
            {"resource_id": "internet",    "via": None},
            {"resource_type": "s3_bucket", "via": "reverse_exposed_to_internet"},
        ],
    },
]


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def _hop_matches(matcher, hop, resource_map):
    """Check whether a single path hop satisfies a chain matcher."""
    via_ok = (matcher.get("via") == hop["via_relationship"])
    if not via_ok:
        return False

    resource = resource_map.get(hop["resource_id"])
    if not resource:
        return False

    if "resource_id" in matcher:
        if resource["id"] != matcher["resource_id"]:
            return False

    if "resource_type" in matcher:
        if resource["type"] != matcher["resource_type"]:
            return False

    return True


def _path_matches_chain(path, chain, resource_map):
    """
    Check whether `path` contains a consecutive subsequence
    that satisfies every matcher in `chain`.
    """
    chain_len = len(chain)
    if len(path) < chain_len:
        return False, []

    for start in range(len(path) - chain_len + 1):
        window = path[start: start + chain_len]
        if all(_hop_matches(chain[i], window[i], resource_map) for i in range(chain_len)):
            return True, window

    return False, []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_attack_paths(resource_map, max_depth=5):
    """
    Traverse the resource graph from every node and check each discovered
    path against all attack path definitions.

    Returns a list of findings shaped the same way as scanner findings,
    plus extra keys:
        - chain : list of {"resource_id", "via_relationship"} dicts
        - description : human-readable explanation of the risk
    """
    findings = []
    seen = set()  # deduplicate: (definition_name, path_tuple)

    for start_id in resource_map:
        for path in traverse(resource_map, start_id, max_depth=max_depth):
            for definition in ATTACK_PATH_DEFINITIONS:
                matched, window = _path_matches_chain(
                    path, definition["chain"], resource_map
                )
                if not matched:
                    continue

                path_key = (
                    definition["name"],
                    tuple(h["resource_id"] for h in window),
                )
                if path_key in seen:
                    continue
                seen.add(path_key)

                findings.append({
                    "policy_name": definition["name"],
                    "severity": definition["severity"],
                    "resource_id": window[0]["resource_id"],
                    "resource_type": resource_map[window[0]["resource_id"]]["type"],
                    "description": definition["description"],
                    "chain": window,
                })

    return findings
