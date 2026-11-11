"""user-permissions-boundary-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "user-permissions-boundary-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A user's permissions boundary attaches, is reflected on GetUser, and clears on delete."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-boundaryuser-")
    policy_name = ctx.unique_name("sim2real-behav-userboundarypolicy-")

    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    boundary_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
    boundary_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(boundary_doc),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=boundary_arn))

    got = iam.get_user(UserName=user_name)["User"]
    assert "PermissionsBoundary" not in got, (
        f"new user must not have a boundary set, got {got.get('PermissionsBoundary')!r}"
    )

    iam.put_user_permissions_boundary(UserName=user_name, PermissionsBoundary=boundary_arn)
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(lambda: iam.delete_user_permissions_boundary(UserName=user_name))
    )

    got = iam.get_user(UserName=user_name)["User"]
    assert got["PermissionsBoundary"]["PermissionsBoundaryArn"] == boundary_arn, (
        f"expected boundary arn {boundary_arn!r}, got {got.get('PermissionsBoundary')!r}"
    )
    assert got["PermissionsBoundary"]["PermissionsBoundaryType"] == "Policy", (
        f"expected boundary type 'Policy', got {got['PermissionsBoundary'].get('PermissionsBoundaryType')!r}"
    )

    iam.delete_user_permissions_boundary(UserName=user_name)

    got = iam.get_user(UserName=user_name)["User"]
    assert "PermissionsBoundary" not in got, (
        f"expected boundary gone after delete, got {got.get('PermissionsBoundary')!r}"
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
