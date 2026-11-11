"""op-contract-simulate-custom-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-simulate-custom-policy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_POLICY_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-bucket/*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::example-bucket/*"},
        ],
    }
)


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SimulateCustomPolicy evaluates allow/explicit-deny/implicit-deny for actions against a raw policy document."""
    iam = ctx.client("iam")

    resp = iam.simulate_custom_policy(
        PolicyInputList=[_POLICY_DOC],
        ActionNames=["s3:GetObject", "s3:DeleteObject", "ec2:DescribeInstances"],
        ResourceArns=["arn:aws:s3:::example-bucket/test-object"],
    )
    decisions = {r["EvalActionName"]: r["EvalDecision"] for r in resp["EvaluationResults"]}

    assert decisions["s3:GetObject"] == "allowed", decisions
    assert decisions["s3:DeleteObject"] == "explicitDeny", decisions
    assert decisions["ec2:DescribeInstances"] == "implicitDeny", decisions

    # Error boundary: a syntactically invalid policy document in the input list is rejected up front.
    code, msg = _error(
        lambda: iam.simulate_custom_policy(
            PolicyInputList=['{"Version": "2012-10-17", "Statement": ['],
            ActionNames=["s3:GetObject"],
        )
    )
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "InvalidInput", f"expected InvalidInput, got {code}"
    want = "Policy input list item 1 has invalid content"
    assert msg == want, f"InvalidInput message: wanted {want!r}, got {msg!r}"


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
