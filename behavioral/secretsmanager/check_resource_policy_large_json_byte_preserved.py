"""resource-policy-large-json-byte-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "resource-policy-large-json-byte-preserved"
GROUP = "representation"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A large, nested resource policy round-trips through Put/GetResourcePolicy as equal JSON.

    The returned document parses to the same structure and content with all eight statements in
    order; the raw string is not compared, so whitespace and key order are not graded.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    root_arn = f"arn:aws:iam::{account_id}:root"

    name = ctx.unique_name("sim2real-behav-respolicy-")
    created = sm.create_secret(Name=name, SecretString="v1")
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    statements = []
    for i in range(8):
        statements.append(
            {
                "Sid": f"AllowAccountRootStatement{i}",
                "Effect": "Allow",
                "Principal": {"AWS": root_arn},
                "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:PrincipalTag/Team": [f"team-{i}-alpha", f"team-{i}-beta"]},
                    "IpAddress": {"aws:SourceIp": ["203.0.113.0/24", "198.51.100.0/24"]},
                    "DateGreaterThan": {"aws:CurrentTime": "2023-01-01T00:00:00Z"},
                    "Bool": {"aws:SecureTransport": "true"},
                },
            }
        )
    policy = {"Version": "2012-10-17", "Statement": statements}

    sm.put_resource_policy(SecretId=arn, ResourcePolicy=json.dumps(policy))
    ctx.on_cleanup(lambda: sm.delete_resource_policy(SecretId=arn))

    resp = sm.get_resource_policy(SecretId=arn)
    returned_policy = json.loads(resp["ResourcePolicy"])

    assert returned_policy == policy, "resource policy content/structure changed on round trip"
    assert len(returned_policy["Statement"]) == 8


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
