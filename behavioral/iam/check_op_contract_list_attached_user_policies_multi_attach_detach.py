"""op-contract-list-attached-user-policies-multi-attach-detach."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

CHECK = "op-contract-list-attached-user-policies-multi-attach-detach"
GROUP = "error-semantics"
SERVICES = ["iam"]


from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAttachedUserPolicies lists every attached managed policy, a detach shows on the next call
    without disturbing the other, and a nonexistent user is rejected with NoSuchEntity.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedUserPolicies.html
    """
    iam = ctx.client("iam")

    resource_tags = [{"Key": "sim2real", "Value": CHECK}]

    user_name = ctx.unique_name("sim2real-user-")
    iam.create_user(UserName=user_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
    policy_arn_a = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-policy-a-"),
        PolicyDocument=json.dumps(policy_doc),
        Tags=resource_tags,
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn_a))
    policy_arn_b = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-policy-b-"),
        PolicyDocument=json.dumps(policy_doc),
        Tags=resource_tags,
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn_b))

    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn_a)
    ctx.on_cleanup(lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn_a))
    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn_b)
    ctx.on_cleanup(
        lambda: _ignore_not_attached(lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn_b))
    )

    resp = iam.list_attached_user_policies(UserName=user_name)
    arns = {p["PolicyArn"] for p in resp["AttachedPolicies"]}
    assert arns == {policy_arn_a, policy_arn_b}, arns

    iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn_b)
    resp2 = iam.list_attached_user_policies(UserName=user_name)
    arns2 = {p["PolicyArn"] for p in resp2["AttachedPolicies"]}
    assert arns2 == {policy_arn_a}, arns2

    missing_user = ctx.unique_name("sim2real-missing-user-")
    code, message = _error(lambda: iam.list_attached_user_policies(UserName=missing_user))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code!r}"
    expected = f"The user with name {missing_user} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The failed probe must leave the real user's remaining attachment unaffected.
    resp3 = iam.list_attached_user_policies(UserName=user_name)
    arns3 = {p["PolicyArn"] for p in resp3["AttachedPolicies"]}
    assert arns3 == {policy_arn_a}, arns3


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_attached(fn):
    """Teardown-only: the body detaches this policy itself, so tolerate it already being detached."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
