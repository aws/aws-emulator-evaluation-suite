"""invalid-policy-arn-on-attach-detach-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-policy-arn-on-attach-detach-rejected"
GROUP = 'errors'
SERVICES = ['iam']

TRUST_POLICY_EC2 = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

# Not ARN-shaped at all, so IAM's ARN-pattern validation fails before any policy-existence check.
MALFORMED_POLICY_ARN = "not-a-valid-policy-arn"
# AWS words the refusal differently on the attach and the detach side.
ATTACH_MALFORMED_MESSAGE = f"ARN {MALFORMED_POLICY_ARN} is not valid."
DETACH_MALFORMED_MESSAGE = "Invalid ARN:  Could not be parsed!"

# Always-present AWS managed policy, used as the positive control.
VALID_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def _err_code(fn):
    """Call fn(); return its ``(code, message)``. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection for a malformed ARN, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Attach/Detach{User,Group,Role}Policy reject a malformed PolicyArn with ValidationError and
    AWS's exact messages, leaving nothing attached; a real managed-policy ARN then attaches and
    detaches cleanly on all three principal types."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    group_name = ctx.unique_name("sim2real-behav-group-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=TRUST_POLICY_EC2)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    attach_cases = [
        ("AttachUserPolicy", lambda: iam.attach_user_policy(UserName=user_name, PolicyArn=MALFORMED_POLICY_ARN)),
        ("AttachGroupPolicy", lambda: iam.attach_group_policy(GroupName=group_name, PolicyArn=MALFORMED_POLICY_ARN)),
        ("AttachRolePolicy", lambda: iam.attach_role_policy(RoleName=role_name, PolicyArn=MALFORMED_POLICY_ARN)),
    ]
    for op_name, fn in attach_cases:
        code, message = _err_code(fn)
        assert code == "ValidationError", f"{op_name}: expected ValidationError for a malformed ARN, got {code}"
        assert message == ATTACH_MALFORMED_MESSAGE, (
            f"{op_name}: expected AWS's exact message {ATTACH_MALFORMED_MESSAGE!r} for a "
            f"malformed ARN, got {message!r}"
        )

    detach_cases = [
        ("DetachUserPolicy", lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=MALFORMED_POLICY_ARN)),
        ("DetachGroupPolicy", lambda: iam.detach_group_policy(GroupName=group_name, PolicyArn=MALFORMED_POLICY_ARN)),
        ("DetachRolePolicy", lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=MALFORMED_POLICY_ARN)),
    ]
    for op_name, fn in detach_cases:
        code, message = _err_code(fn)
        assert code == "ValidationError", f"{op_name}: expected ValidationError for a malformed ARN, got {code}"
        assert message == DETACH_MALFORMED_MESSAGE, (
            f"{op_name}: expected AWS's exact message {DETACH_MALFORMED_MESSAGE!r} for a "
            f"malformed ARN, got {message!r}"
        )

    assert iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"] == []
    assert iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"] == []
    assert iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"] == []

    # Positive control: the same calls with a real ARN succeed, so the rejections are ARN-specific.
    iam.attach_user_policy(UserName=user_name, PolicyArn=VALID_POLICY_ARN)
    attached = [p["PolicyArn"] for p in iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]]
    assert VALID_POLICY_ARN in attached, f"positive control: {VALID_POLICY_ARN} not attached to user, saw {attached}"
    iam.detach_user_policy(UserName=user_name, PolicyArn=VALID_POLICY_ARN)

    iam.attach_group_policy(GroupName=group_name, PolicyArn=VALID_POLICY_ARN)
    attached = [p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]]
    assert VALID_POLICY_ARN in attached, f"positive control: {VALID_POLICY_ARN} not attached to group, saw {attached}"
    iam.detach_group_policy(GroupName=group_name, PolicyArn=VALID_POLICY_ARN)

    iam.attach_role_policy(RoleName=role_name, PolicyArn=VALID_POLICY_ARN)
    attached = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]]
    assert VALID_POLICY_ARN in attached, f"positive control: {VALID_POLICY_ARN} not attached to role, saw {attached}"
    iam.detach_role_policy(RoleName=role_name, PolicyArn=VALID_POLICY_ARN)

    assert iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"] == []
    assert iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"] == []
    assert iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"] == []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
