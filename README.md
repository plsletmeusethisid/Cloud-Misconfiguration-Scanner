# Cloud Misconfiguration Scanner

A graph-based AWS security analysis tool that models cloud infrastructure as a directed graph, evaluates security policies through a custom DSL, and detects multi-hop attack paths that single-resource checks cannot catch.

---

## Overview

Most cloud security scanners check resources in isolation — flag an open port here, a public bucket there. This scanner models the relationships *between* resources, enabling it to detect chained risk scenarios like:

```
Internet → open port → EC2 instance → admin IAM role
```

That chain represents a full privilege escalation path from the public internet to admin access — a critical finding that only emerges when you look at the infrastructure as a connected graph.

---

## Architecture

```
Raw AWS Data
    ↓
Normalization Layer       models/  normalizers/
    ↓
Relationship Graph        relationships/
    ↓
         ┌──────────────────────┬─────────────────────┐
         ↓                      ↓
    DSL Engine            Graph Traversal
    policy_engine/        graph/
         ↓                      ↓
    Policy Findings       Attack Path Detection
                          scanner/attack_paths.py
         └──────────────────────┘
                    ↓
             Merged Report
             scanner/reporter.py
```

### Key Components

**Normalization Layer** (`normalizers/`)
Each AWS resource type (EC2, S3, IAM, Security Groups) is normalized into a consistent schema:
```python
{
    "id": "sg-123",
    "type": "security_group",
    "provider": "aws",
    "region": None,
    "config": { ... },
    "relationships": [ ... ]
}
```

**Relationship Graph** (`relationships/builder.py`)
After normalization, a second pass builds reverse edges automatically. If EC2 → `uses_security_group` → SG, the SG also receives a `reverse_uses_security_group` edge back to the EC2. This makes the graph traversable in both directions.

A synthetic `internet` node is added as a target for any publicly exposed resource, making internet exposure detectable through the same generic relationship logic.

**DSL Engine** (`policy_engine/`)
A three-stage pipeline — tokenizer → parser → evaluator — compiles policy strings into ASTs and evaluates them against resources. New security rules require zero code changes; just add an entry to `scanner/policies.py`.

Example policy:
```
resource.type == "security_group" AND
EXISTS config.inbound_rules WHERE port == 22 AND is_public == true
```

**Graph Traversal** (`graph/traversal.py`)
An iterative DFS that walks the resource graph from a given start node up to a configurable max depth, yielding every path as a list of `(resource_id, via_relationship)` hops.

**Attack Path Detection** (`scanner/attack_paths.py`)
Defines dangerous chains as sequences of hop matchers and checks every traversed path for matches. New attack patterns are added declaratively — no imperative logic required.

Example definition:
```python
{
    "name": "Internet → Open Port → Compute → Admin IAM Role",
    "severity": "CRITICAL_PATH",
    "chain": [
        {"resource_id": "internet",           "via": None},
        {"resource_type": "security_group",   "via": "allows_ingress"},
        {"resource_type": "compute_instance", "via": "reverse_uses_security_group"},
        {"resource_type": "iam_role",         "via": "assumes_role"},
    ],
}
```

---

## Project Structure

```
project/
│
├── models/
│   └── resource.py               # Base resource schema
│
├── normalizers/
│   ├── security_group.py
│   ├── ec2.py
│   ├── s3.py
│   └── iam.py
│
├── relationships/
│   └── builder.py                # Reverse edge construction
│
├── graph/
│   └── traversal.py              # Depth-limited iterative DFS
│
├── policy_engine/
│   ├── tokenizer.py              # Regex-based lexer
│   ├── parser.py                 # Token → AST
│   ├── evaluator.py              # AST evaluation against resources
│   └── engine.py                 # Pipeline entry point
│
├── scanner/
│   ├── policies.py               # DSL policy definitions
│   ├── scanner.py                # Policy runner
│   ├── attack_paths.py           # Chain-based attack path detection
│   └── reporter.py               # Severity-ranked output
│
├── pipeline.py                   # Normalization + graph construction
└── main.py                       # Entry point
```

---

## Usage

### Run with sample data

```bash
python main.py
```

The sample data in `main.py` includes a security group with SSH open to `0.0.0.0/0`, an EC2 instance using that group with an admin IAM role attached, and a public unencrypted S3 bucket — enough to trigger all built-in detections.

### Expected output

```
============================================================
  ⛓  ATTACK PATHS DETECTED
============================================================

[CRITICAL_PATH] Internet → Open Port → Compute → Admin IAM Role
Entry Point : internet (external)
Risk        : An internet-reachable entry point leads through a permissive
              security group into a compute instance that assumes an admin IAM role.
Chain:
                    START  →  internet
               allows_ingress  →  sg-123
  reverse_uses_security_group  →  i-abc
                 assumes_role  →  admin-role

============================================================
  🔍  POLICY FINDINGS
============================================================

[CRITICAL] Public S3 without encryption
Resource: public-bucket (s3_bucket)

[HIGH] Open SSH
Resource: sg-123 (security_group)

[HIGH] Internet Exposure
Resource: sg-123 (security_group)
```

---

## Adding New Policies

Add an entry to `scanner/policies.py` using the DSL:

```python
{
    "name": "Admin IAM Role",
    "severity": "HIGH",
    "rule": '''
        resource.type == "iam_role" AND
        config.is_admin == true
    '''
}
```

## Adding New Attack Path Definitions

Add an entry to `ATTACK_PATH_DEFINITIONS` in `scanner/attack_paths.py`:

```python
{
    "name": "Internet → Public S3 Bucket (Unencrypted)",
    "severity": "CRITICAL_PATH",
    "description": "A publicly exposed S3 bucket with no encryption is directly reachable from the internet.",
    "chain": [
        {"resource_id": "internet",    "via": None},
        {"resource_type": "s3_bucket", "via": "reverse_exposed_to_internet"},
    ],
}
```

## Adding New Resource Types

1. Create a normalizer in `normalizers/` that calls `create_resource()` and populates `config` and `relationships`
2. Register it in `pipeline.py`

The DSL engine, traversal, and attack path detection require no changes.

---

## DSL Reference

| Syntax | Description |
|---|---|
| `resource.type == "s3_bucket"` | Match on top-level resource field |
| `config.public == true` | Match on nested config field |
| `EXISTS config.inbound_rules WHERE port == 22` | Check if any item in a list matches a condition |
| `AND`, `OR`, `NOT` | Boolean operators |

---

## Supported Resource Types

| Type | Normalizer | Detects |
|---|---|---|
| Security Group | `normalizers/security_group.py` | Open ports, public ingress rules |
| EC2 Instance | `normalizers/ec2.py` | Public IP, SG associations, IAM role assumptions |
| S3 Bucket | `normalizers/s3.py` | Public access, missing encryption |
| IAM Role | `normalizers/iam.py` | Wildcard actions, admin privileges |
