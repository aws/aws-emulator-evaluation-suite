"""op-contract-list-attached-role-policies-multi-attach-detach."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

CHECK = "op-contract-list-attached-role-policies-multi-attach-detach"
GROUP = "error-semantics"
SERVICES = ["iam"]


from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAttachedRolePolicies lists both attached managed policies and, after one
    detach, only the other; a nonexistent role name fails with NoSuchEntity and its
    exact message."""
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    policy_arn_a = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-policy-a-"), PolicyDocument=json.dumps(policy_doc)
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn_a))
    policy_arn_b = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-policy-b-"), PolicyDocument=json.dumps(policy_doc)
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn_b))

    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn_a)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn_a))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn_b)
    ctx.on_cleanup(
        lambda: _ignore_not_attached(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn_b))
    )

    resp = iam.list_attached_role_policies(RoleName=role_name)
    arns = {p["PolicyArn"] for p in resp["AttachedPolicies"]}
    assert arns == {policy_arn_a, policy_arn_b}, (
        f"expected both attached policies {{{policy_arn_a!r}, {policy_arn_b!r}}}, got {arns!r}"
    )

    # detaching one policy is reflected on the very next call, the other is untouched
    iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn_b)
    resp2 = iam.list_attached_role_policies(RoleName=role_name)
    arns2 = {p["PolicyArn"] for p in resp2["AttachedPolicies"]}
    assert arns2 == {policy_arn_a}, (
        f"expected only {policy_arn_a!r} to remain attached after detaching {policy_arn_b!r}, "
        f"got {arns2!r}"
    )

    missing_role = ctx.unique_name("sim2real-missing-role-")
    code, message = _error(lambda: iam.list_attached_role_policies(RoleName=missing_role))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code!r}"
    expected = f"The role with name {missing_role} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the real role's remaining attachment is unaffected by the failed probe
    resp3 = iam.list_attached_role_policies(RoleName=role_name)
    final_arns = {p["PolicyArn"] for p in resp3["AttachedPolicies"]}
    assert final_arns == {policy_arn_a}, (
        f"expected {policy_arn_a!r} still attached after the failed NoSuchEntity probe on "
        f"{missing_role!r}, got {final_arns!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
