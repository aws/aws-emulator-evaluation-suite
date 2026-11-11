"""policy-invalid-effect."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

CHECK = "policy-invalid-effect"
GROUP = 'policy_document_validation'
SERVICES = ['iam']

ERR_MALFORMED_POLICY = "MalformedPolicyDocument"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _statement(effect):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": effect,
                    "Action": "iam:GetUser",
                    "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
                }
            ],
        }
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePolicy with an Effect other than Allow/Deny fails MalformedPolicyDocument and persists
    nothing, while the same statement with Effect=Allow is accepted."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    good_name = ctx.unique_name("sim2real-behav-pol-good-")
    good_arn = iam.create_policy(PolicyName=good_name, PolicyDocument=_statement("Allow"))["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=good_arn))
    assert good_arn == f"arn:aws:iam::{account_id}:policy/{good_name}", (
        f"positive control: expected a policy ARN for {good_name}, got {good_arn!r}"
    )

    bad_name = ctx.unique_name("sim2real-behav-pol-bad-")
    bad_arn = f"arn:aws:iam::{account_id}:policy/{bad_name}"
    ctx.on_cleanup(lambda: _best_effort_delete_policy(iam, bad_arn))
    try:
        iam.create_policy(PolicyName=bad_name, PolicyDocument=_statement("Maybe"))
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_MALFORMED_POLICY, f"Expected {ERR_MALFORMED_POLICY}, got {code!r}"
    assert message == "Syntax errors in policy.", (
        f"expected the exact MalformedPolicyDocument message AWS returns, got {message!r}"
    )

    absent_code = None
    try:
        iam.get_policy(PolicyArn=bad_arn)
    except ClientError as exc:
        absent_code = exc.response.get("Error", {}).get("Code")
        absent_message = exc.response.get("Error", {}).get("Message")
    assert absent_code == ERR_NO_SUCH_ENTITY, (
        f"rejected CreatePolicy must not persist a policy at {bad_arn}, get_policy gave {absent_code!r}"
    )
    assert absent_message == f"Policy {bad_arn} was not found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {absent_message!r}"
    )


def _best_effort_delete_policy(iam, policy_arn: str) -> None:
    try:
        iam.delete_policy(PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
