"""put-role-permissions-boundary-overwrite-replaces-previous-boundary."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-role-permissions-boundary-overwrite-replaces-previous-boundary"
GROUP = "state-machine"
SERVICES = ["iam"]

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PutRolePermissionsBoundary call replaces the boundary wholesale: GetRole
    reflects only the new policy, never the two together."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-boundaryswap-")

    first_doc = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    second_doc = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:GetQueueUrl", "Resource": "*"}]})
    first_name = ctx.unique_name("sim2real-behav-boundary-first-")
    second_name = ctx.unique_name("sim2real-behav-boundary-second-")

    first_arn = iam.create_policy(PolicyName=first_name, PolicyDocument=first_doc)["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=first_arn))
    second_arn = iam.create_policy(PolicyName=second_name, PolicyDocument=second_doc)["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=second_arn))

    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=first_arn)
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role_permissions_boundary(RoleName=role_name)))

    after_first = iam.get_role(RoleName=role_name)["Role"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert after_first == first_arn, f"expected the first boundary {first_arn!r} on an independent GetRole, got {after_first!r}"

    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=second_arn)

    after_second = iam.get_role(RoleName=role_name)["Role"]["PermissionsBoundary"]
    assert after_second["PermissionsBoundaryArn"] == second_arn, (
        f"expected the overwrite to replace the boundary with {second_arn!r}, "
        f"got {after_second['PermissionsBoundaryArn']!r}"
    )
    assert after_second["PermissionsBoundaryType"] == "Policy", (
        f"expected PermissionsBoundaryType 'Policy' after the overwrite, got {after_second['PermissionsBoundaryType']!r}"
    )

    iam.delete_role_permissions_boundary(RoleName=role_name)
    cleared = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in cleared, (
        f"expected no boundary after delete, got {cleared.get('PermissionsBoundary')!r}"
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
