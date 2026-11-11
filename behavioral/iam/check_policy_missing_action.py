"""policy-missing-action."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

CHECK = "policy-missing-action"
GROUP = 'policy_document_validation'
SERVICES = ['iam']

ERR_MALFORMED_POLICY = "MalformedPolicyDocument"
ERR_NOT_FOUND = "NoSuchEntity"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePolicy with a Statement missing Action/NotAction fails MalformedPolicyDocument and
    persists nothing, while the same document with Action is accepted."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    good_name = ctx.unique_name("sim2real-behav-pol-good-")
    good_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:GetUser",
                    "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
                }
            ],
        }
    )
    good_arn = iam.create_policy(
        PolicyName=good_name, PolicyDocument=good_doc, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=good_arn))
    got = iam.get_policy(PolicyArn=good_arn)["Policy"]["PolicyName"]
    assert got == good_name, f"positive control: expected {good_name} to exist, got {got!r}"

    bad_name = ctx.unique_name("sim2real-behav-pol-")
    bad_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
                }
            ],
        }
    )
    try:
        resp = iam.create_policy(
            PolicyName=bad_name, PolicyDocument=bad_doc, Tags=[{"Key": "sim2real", "Value": CHECK}]
        )
        arn = resp["Policy"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=arn))
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_MALFORMED_POLICY, f"Expected {ERR_MALFORMED_POLICY}, got {code!r}"
    assert message == "Policy statement must contain actions.", (
        f"expected the exact MalformedPolicyDocument message AWS returns, got {message!r}"
    )

    bad_arn = f"arn:aws:iam::{account_id}:policy/{bad_name}"
    try:
        iam.get_policy(PolicyArn=bad_arn)
        not_found_code = None
        not_found_message = None
    except ClientError as exc:
        not_found_code = exc.response.get("Error", {}).get("Code")
        not_found_message = exc.response.get("Error", {}).get("Message")
    assert not_found_code == ERR_NOT_FOUND, (
        f"rejected CreatePolicy must not persist a policy: expected {ERR_NOT_FOUND} on an "
        f"independent read, got {not_found_code!r}"
    )
    assert not_found_message == f"Policy {bad_arn} was not found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {not_found_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
