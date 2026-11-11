"""role-permissions-boundary-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "role-permissions-boundary-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A role's permissions boundary attaches, is reflected on GetRole, and clears on delete."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-boundaryrole-")
    policy_name = ctx.unique_name("sim2real-behav-boundarypolicy-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    boundary_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    boundary_arn = iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(boundary_doc))[
        "Policy"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=boundary_arn))

    got = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in got, (
        f"freshly created role must not report a boundary, got {got.get('PermissionsBoundary')}"
    )

    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=boundary_arn)
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role_permissions_boundary(RoleName=role_name)))

    got = iam.get_role(RoleName=role_name)["Role"]
    assert got["PermissionsBoundary"]["PermissionsBoundaryArn"] == boundary_arn, (
        f"expected PermissionsBoundaryArn {boundary_arn!r}, "
        f"got {got.get('PermissionsBoundary')!r}"
    )
    assert got["PermissionsBoundary"]["PermissionsBoundaryType"] == "Policy", (
        f"expected PermissionsBoundaryType 'Policy', got {got['PermissionsBoundary'].get('PermissionsBoundaryType')!r}"
    )

    iam.delete_role_permissions_boundary(RoleName=role_name)

    got = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in got, (
        f"expected boundary gone after delete, got {got.get('PermissionsBoundary')}"
    )


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
