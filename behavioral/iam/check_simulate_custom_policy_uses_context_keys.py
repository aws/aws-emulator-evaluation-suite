"""simulate-custom-policy-uses-context-keys."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "simulate-custom-policy-uses-context-keys"
GROUP = "policy_simulation"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetContextKeysForCustomPolicy lists exactly the policy's condition keys; SimulateCustomPolicy
    allows with a satisfying context but returns implicitDeny when aws:SourceIp does not match."""
    iam = ctx.client("iam")
    bucket_arn = "arn:aws:s3:::sim2real-context-key-bucket/object.txt"
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": bucket_arn,
            "Condition": {
                "StringEquals": {"s3:x-amz-server-side-encryption": "aws:kms"},
                "IpAddress": {"aws:SourceIp": "10.0.0.0/24"},
            },
        }],
    })

    keys = set(iam.get_context_keys_for_custom_policy(PolicyInputList=[policy_doc])["ContextKeyNames"])
    expected_keys = {"s3:x-amz-server-side-encryption", "aws:SourceIp"}
    assert keys == expected_keys, (
        f"expected ContextKeyNames to be exactly {expected_keys!r} (the two Condition-block keys "
        f"the policy document references), got {keys!r}"
    )

    satisfying_context = [
        {"ContextKeyName": "aws:SourceIp", "ContextKeyType": "ip", "ContextKeyValues": ["10.0.0.5"]},
        {
            "ContextKeyName": "s3:x-amz-server-side-encryption",
            "ContextKeyType": "string",
            "ContextKeyValues": ["aws:kms"],
        },
    ]
    allowed = iam.simulate_custom_policy(
        PolicyInputList=[policy_doc],
        ActionNames=["s3:PutObject"],
        ResourceArns=[bucket_arn],
        ContextEntries=satisfying_context,
    )["EvaluationResults"]
    assert len(allowed) == 1, f"expected exactly one EvaluationResult, got {allowed!r}"
    assert allowed[0]["EvalDecision"] == "allowed", (
        "a context satisfying every referenced Condition key must grant; expected 'allowed', got "
        f"{allowed[0]['EvalDecision']!r}"
    )

    mismatching_context = [
        {"ContextKeyName": "aws:SourceIp", "ContextKeyType": "ip", "ContextKeyValues": ["203.0.113.9"]},
        {
            "ContextKeyName": "s3:x-amz-server-side-encryption",
            "ContextKeyType": "string",
            "ContextKeyValues": ["aws:kms"],
        },
    ]
    denied = iam.simulate_custom_policy(
        PolicyInputList=[policy_doc],
        ActionNames=["s3:PutObject"],
        ResourceArns=[bucket_arn],
        ContextEntries=mismatching_context,
    )["EvaluationResults"]
    assert len(denied) == 1, f"expected exactly one EvaluationResult, got {denied!r}"
    assert denied[0]["EvalDecision"] == "implicitDeny", (
        "aws:SourceIp was supplied but does not satisfy the Condition, so the same statement must "
        f"flip to 'implicitDeny'; got {denied[0]['EvalDecision']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
