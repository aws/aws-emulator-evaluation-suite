"""op-contract-putResourcePolicy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-putResourcePolicy"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """PutResourcePolicy: success path creates an account-scoped resource policy
    that round-trips via DescribeResourcePolicies; distinct error boundary is
    InvalidParameterException for a malformed policyDocument."""
    logs = ctx.client("logs")
    policy_name = ctx.unique_name("sim2real-behav-rp-")
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealBehavioralTest",
                    "Effect": "Allow",
                    "Principal": {"Service": ["route53.amazonaws.com"]},
                    "Action": "logs:PutLogEvents",
                    "Resource": "*",
                }
            ],
        }
    )

    resp = logs.put_resource_policy(policyName=policy_name, policyDocument=policy_document)
    assert resp["resourcePolicy"]["policyName"] == policy_name
    ctx.on_cleanup(lambda: logs.delete_resource_policy(policyName=policy_name))

    described = logs.describe_resource_policies()
    matches = [p for p in described["resourcePolicies"] if p["policyName"] == policy_name]
    assert len(matches) == 1, f"expected exactly one resource policy, got {matches}"
    stored_doc = json.loads(matches[0]["policyDocument"])
    assert stored_doc["Statement"][0]["Sid"] == "Sim2RealBehavioralTest"

    # Distinct error boundary: malformed (non-JSON) policyDocument.
    code, message = _client_error(
        lambda: logs.put_resource_policy(
            policyName=ctx.unique_name("sim2real-behav-rp2-"),
            policyDocument="{not-valid-json:::",
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        "Error occurred while parsing accessPolicy. Please check if the accessPolicy has been "
        "constructed correctly using IAM grammar."
    ), f"unexpected message: {message!r}"


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
