"""op-contract-simulate-principal-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-simulate-principal-policy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SimulatePrincipalPolicy evaluates the real policies attached to a role, not just a supplied document."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_DOC,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-inline-policy"
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "arn:aws:sqs:*:*:example-queue-*"}
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    def decisions():
        resp = iam.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=["sqs:SendMessage", "sqs:DeleteQueue"],
            ResourceArns=["arn:aws:sqs:us-east-1:123456789012:example-queue-test"],
        )
        return {r["EvalActionName"]: r["EvalDecision"] for r in resp["EvaluationResults"]}

    # The inline attachment is eventually consistent for the simulator; poll for the allow.
    deadline = time.monotonic() + 30
    result = decisions()
    while time.monotonic() < deadline:
        if result.get("sqs:SendMessage") == "allowed":
            break
        time.sleep(3)
        result = decisions()
    assert result["sqs:SendMessage"] == "allowed", result
    assert result["sqs:DeleteQueue"] == "implicitDeny", result

    # Error boundary: PolicySourceArn must reference a real IAM entity.
    ghost_name = ctx.unique_name("sim2real-ghost-role-")
    bogus_arn = role_arn.rsplit("/", 1)[0] + "/" + ghost_name
    code, message = _error(
        lambda: iam.simulate_principal_policy(PolicySourceArn=bogus_arn, ActionNames=["sqs:SendMessage"])
    )
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = "Unable to retrieve specified IAM entity."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
