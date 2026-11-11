"""non-attachable-policy-boundary-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "non-attachable-policy-boundary-rejected"
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

# A non-attachable AWS-managed policy: it belongs to a service-linked role and is documented
# ("You cannot attach this policy to your users, groups, or roles.") to be rejected by
# Put*PermissionsBoundary with PolicyNotAttachable.
NON_ATTACHABLE_POLICY_ARN = "arn:aws:iam::aws:policy/aws-service-role/AWSAuditManagerServiceRolePolicy"

# Positive control: an ordinary attachable AWS-managed policy, used to prove the account and
# credentials can otherwise set a permissions boundary at all -- without this, a rejection of
# NON_ATTACHABLE_POLICY_ARN is indistinguishable from "every PutPermissionsBoundary call fails".
READONLY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def _err_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting what real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected PolicyNotAttachable, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRolePermissionsBoundary and PutUserPermissionsBoundary with a non-attachable
    AWS-reserved policy fail with PolicyNotAttachable and the exact message and set no
    boundary; ReadOnlyAccess is accepted and read back as the boundary of both."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=TRUST_POLICY_EC2,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    code_role, message_role = _err_code(
        lambda: iam.put_role_permissions_boundary(
            RoleName=role_name, PermissionsBoundary=NON_ATTACHABLE_POLICY_ARN
        )
    )
    assert code_role == "PolicyNotAttachable", (
        f"PutRolePermissionsBoundary: expected PolicyNotAttachable, got {code_role}"
    )
    assert message_role == "Cannot attach AWS reserved policy to an IAM role.", message_role
    got_role = iam.get_role(RoleName=role_name)
    assert "PermissionsBoundary" not in got_role["Role"], "rejected boundary must not be set on the role"

    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=READONLY_ARN)
    ctx.on_cleanup(lambda: iam.delete_role_permissions_boundary(RoleName=role_name))
    role_with_boundary = iam.get_role(RoleName=role_name)["Role"]
    actual_role_boundary = role_with_boundary["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert actual_role_boundary == READONLY_ARN, (
        f"positive control: expected the attachable policy {READONLY_ARN!r} reflected as the "
        f"role's boundary on an independent GetRole, got {actual_role_boundary!r}"
    )

    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    code_user, message_user = _err_code(
        lambda: iam.put_user_permissions_boundary(
            UserName=user_name, PermissionsBoundary=NON_ATTACHABLE_POLICY_ARN
        )
    )
    assert code_user == "PolicyNotAttachable", (
        f"PutUserPermissionsBoundary: expected PolicyNotAttachable, got {code_user}"
    )
    assert message_user == "Cannot attach AWS reserved policy to an IAM user.", message_user
    got_user = iam.get_user(UserName=user_name)
    assert "PermissionsBoundary" not in got_user["User"], "rejected boundary must not be set on the user"

    iam.put_user_permissions_boundary(UserName=user_name, PermissionsBoundary=READONLY_ARN)
    ctx.on_cleanup(lambda: iam.delete_user_permissions_boundary(UserName=user_name))
    user_with_boundary = iam.get_user(UserName=user_name)["User"]
    actual_user_boundary = user_with_boundary["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert actual_user_boundary == READONLY_ARN, (
        f"positive control: expected the attachable policy {READONLY_ARN!r} reflected as the "
        f"user's boundary on an independent GetUser, got {actual_user_boundary!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
