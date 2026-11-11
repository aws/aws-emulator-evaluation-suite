"""permissions-boundary-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "permissions-boundary-lifecycle"
GROUP = 'permissions_boundaries'
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

ALLOW_S3_LIST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
)


def _err_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected NoSuchEntity, but the call SUCCEEDED and returned {result!r}")


def _tolerate_gone(fn):
    """Teardown-only: the body detaches each boundary itself, so tolerate it already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Put{Role,User}PermissionsBoundary sets a boundary shown by GetRole/GetUser and
    Delete*PermissionsBoundary removes it; a nonexistent boundary ARN fails NoSuchEntity with
    AWS's exact message and sets nothing."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    user_name = ctx.unique_name("sim2real-behav-user-")
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=TRUST_POLICY_EC2,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    policy_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=ALLOW_S3_LIST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    got_role0 = iam.get_role(RoleName=role_name)
    assert "PermissionsBoundary" not in got_role0["Role"], "new role must not have a boundary set"
    got_user0 = iam.get_user(UserName=user_name)
    assert "PermissionsBoundary" not in got_user0["User"], "new user must not have a boundary set"

    fake_arn = policy_arn[:-8] + "deadbeef"
    code, message = _err_code(
        lambda: iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=fake_arn)
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a bogus boundary ARN, got {code}"
    expected = f"Scope ARN: {fake_arn} does not exist or is not attachable."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    got_role_unchanged = iam.get_role(RoleName=role_name)
    assert "PermissionsBoundary" not in got_role_unchanged["Role"], (
        "rejected Put must not set a boundary"
    )

    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=policy_arn)
    ctx.on_cleanup(
        lambda: _tolerate_gone(lambda: iam.delete_role_permissions_boundary(RoleName=role_name))
    )
    got_role = iam.get_role(RoleName=role_name)
    actual_role_boundary = got_role["Role"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert actual_role_boundary == policy_arn, (
        f"expected role boundary {policy_arn!r} reflected on an independent GetRole, "
        f"got {actual_role_boundary!r}"
    )

    iam.put_user_permissions_boundary(UserName=user_name, PermissionsBoundary=policy_arn)
    ctx.on_cleanup(
        lambda: _tolerate_gone(lambda: iam.delete_user_permissions_boundary(UserName=user_name))
    )
    got_user = iam.get_user(UserName=user_name)
    actual_user_boundary = got_user["User"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert actual_user_boundary == policy_arn, (
        f"expected user boundary {policy_arn!r} reflected on an independent GetUser, "
        f"got {actual_user_boundary!r}"
    )

    iam.delete_role_permissions_boundary(RoleName=role_name)
    got_role2 = iam.get_role(RoleName=role_name)
    assert "PermissionsBoundary" not in got_role2["Role"], (
        f"expected boundary gone after delete, got {got_role2['Role'].get('PermissionsBoundary')}"
    )

    iam.delete_user_permissions_boundary(UserName=user_name)
    got_user2 = iam.get_user(UserName=user_name)
    assert "PermissionsBoundary" not in got_user2["User"], (
        f"expected boundary gone after delete, got {got_user2['User'].get('PermissionsBoundary')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
