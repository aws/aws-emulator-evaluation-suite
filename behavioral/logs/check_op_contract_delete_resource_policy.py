"""op-contract-deleteResourcePolicy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-deleteResourcePolicy"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """DeleteResourcePolicy: success removes the named policy from
    DescribeResourcePolicies; deleting a policy name that was never created
    reports ResourceNotFoundException."""
    logs = ctx.client("logs")
    policy_name = ctx.unique_name("sim2real-behav-drp-")
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realBehavAllow",
                    "Effect": "Allow",
                    "Principal": {"Service": "es.amazonaws.com"},
                    "Action": "logs:PutLogEvents",
                    "Resource": "*",
                }
            ],
        }
    )

    logs.put_resource_policy(policyName=policy_name, policyDocument=policy_document)

    def _cleanup():
        for policy in logs.describe_resource_policies()["resourcePolicies"]:
            if policy["policyName"] == policy_name:
                logs.delete_resource_policy(policyName=policy_name)
                break

    ctx.on_cleanup(_cleanup)

    logs.delete_resource_policy(policyName=policy_name)
    remaining = [
        p
        for p in logs.describe_resource_policies()["resourcePolicies"]
        if p["policyName"] == policy_name
    ]
    assert remaining == [], f"resource policy still present after delete: {remaining}"

    code, message = _error(lambda: logs.delete_resource_policy(policyName=policy_name))
    assert code == "ResourceNotFoundException", f"got {code!r}"
    assert message == f"Policy with name [{policy_name}] does not exist.", (
        f"unexpected message: {message!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
