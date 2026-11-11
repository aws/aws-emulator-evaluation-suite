"""delete-nonexistent-resource-policy-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")

CHECK = "delete-nonexistent-resource-policy-fails"
GROUP = 'resource-policy'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """A resource policy is listed after PutResourcePolicy and unlisted after DeleteResourcePolicy, and a second
    delete raises ResourceNotFoundException with its exact message."""
    logs = ctx.client("logs")
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealBehavioral",
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
        try:
            logs.delete_resource_policy(policyName=policy_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    def _has_policy():
        return any(
            p["policyName"] == policy_name
            for p in logs.describe_resource_policies()["resourcePolicies"]
        )

    assert _has_policy(), f"{policy_name} not visible via DescribeResourcePolicies after PutResourcePolicy"

    logs.delete_resource_policy(policyName=policy_name)
    assert not _has_policy(), f"{policy_name} still present after DeleteResourcePolicy"

    error = _expect_error(lambda: logs.delete_resource_policy(policyName=policy_name))
    assert error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error!r}"
    expected_message = f"Policy with name [{policy_name}] does not exist."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
