"""op-contract-describe-resource-policies."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-resource-policies"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """DescribeResourcePolicies lists an account-scoped policy with its policyDocument, and rejects
    a limit above the documented maximum of 50 with InvalidParameterException."""
    logs = ctx.client("logs")
    policy_name = ctx.unique_name("sim2real-behav-rp-")
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealBehavioral",
                    "Effect": "Allow",
                    "Principal": {"Service": ["route53.amazonaws.com"]},
                    "Action": "logs:PutLogEvents",
                    "Resource": "*",
                }
            ],
        }
    )

    logs.put_resource_policy(policyName=policy_name, policyDocument=policy_document)
    ctx.on_cleanup(lambda: logs.delete_resource_policy(policyName=policy_name))

    resp = logs.describe_resource_policies()
    by_name = {p["policyName"]: p for p in resp["resourcePolicies"]}
    assert policy_name in by_name, "resource policy not visible in DescribeResourcePolicies"
    entry = by_name[policy_name]
    # AWS normalizes single-element JSON arrays (e.g. a lone Principal.Service value) to a
    # bare scalar in the stored policyDocument, so compare structurally-equivalent forms
    # rather than requiring byte-for-byte list-vs-scalar identity.
    stored_doc = _normalize(json.loads(entry["policyDocument"]))
    expected_doc = _normalize(json.loads(policy_document))
    assert stored_doc == expected_doc, f"stored policyDocument {stored_doc} != submitted {expected_doc}"

    # botocore validates only the range minimum client-side, so limit=51 reaches the service.
    code, message = _expect_error(lambda: logs.describe_resource_policies(limit=51))
    assert code == "InvalidParameterException", f"expected limit=51 to be rejected with InvalidParameterException, got {code}"
    expected = "1 validation error detected: Value at 'limit' failed to satisfy constraint: Member must have value less than or equal to 50"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _normalize(obj):
    """Collapse single-element lists to their bare element, recursively, so structurally
    equivalent JSON policy documents compare equal regardless of AWS's list/scalar
    normalization of single-value fields (e.g. Principal.Service)."""
    if isinstance(obj, list):
        normalized = [_normalize(v) for v in obj]
        return normalized[0] if len(normalized) == 1 else normalized
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items()}
    return obj


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
