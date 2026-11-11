"""role-permissions-boundary-invalid-arn-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "role-permissions-boundary-invalid-arn-rejected"
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

_VALID_BOUNDARY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRolePermissionsBoundary rejects a PermissionsBoundary ARN that does not exist with
    NoSuchEntity and leaves the role's boundary state untouched; the same call with a real
    managed-policy ARN (positive control) succeeds and is visible on GetRole."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-badboundaryrole-")

    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    caller_account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:iam::{caller_account}:policy/sim2real-does-not-exist-{role_name}"

    code, message = _error(
        lambda: iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=bogus_arn)
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent boundary ARN, got {code!r}"
    want = f"Scope ARN: {bogus_arn} does not exist or is not attachable."
    assert message == want, f"NoSuchEntity message: expected {want!r}, got {message!r}"

    # the rejected call must not have mutated the role
    role = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in role, (
        f"rejected PutRolePermissionsBoundary must not set a boundary, got {role.get('PermissionsBoundary')!r}"
    )

    # positive control: the identical call with a real managed policy ARN succeeds
    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=_VALID_BOUNDARY_ARN)
    ctx.on_cleanup(lambda: iam.delete_role_permissions_boundary(RoleName=role_name))
    role2 = iam.get_role(RoleName=role_name)["Role"]
    actual_boundary_arn = role2["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert actual_boundary_arn == _VALID_BOUNDARY_ARN, (
        f"expected the positive-control policy {_VALID_BOUNDARY_ARN!r} reflected as the role's "
        f"boundary on an independent GetRole, got {actual_boundary_arn!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting what real AWS rejects is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected NoSuchEntity, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
