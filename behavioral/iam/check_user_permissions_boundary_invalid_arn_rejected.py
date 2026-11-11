"""user-permissions-boundary-invalid-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "user-permissions-boundary-invalid-arn-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

_VALID_BOUNDARY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
_MSG_BOGUS = "Scope ARN: {arn} does not exist or is not attachable."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutUserPermissionsBoundary with a nonexistent policy ARN is rejected with NoSuchEntity and
    leaves the user's boundary state untouched; the same call with a real managed-policy ARN
    (positive control) succeeds and is visible on GetUser.
    """
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:iam::{account_id}:policy/sim2real-does-not-exist-boundary"

    try:
        result = iam.put_user_permissions_boundary(UserName=user_name, PermissionsBoundary=bogus_arn)
    except ClientError as e:
        err = e.response.get("Error", {})
    else:
        raise AssertionError(f"expected the bogus boundary ARN to be rejected, but it SUCCEEDED: {result!r}")
    assert err.get("Code") == "NoSuchEntity", f"expected NoSuchEntity for bogus boundary ARN, got {err!r}"
    expected_msg = _MSG_BOGUS.format(arn=bogus_arn)
    assert err.get("Message") == expected_msg, (err.get("Message"), expected_msg)

    # the forbidden effect did not happen: user still has no boundary
    user = iam.get_user(UserName=user_name)["User"]
    assert "PermissionsBoundary" not in user, (
        f"expected no PermissionsBoundary after rejected PutUserPermissionsBoundary, got {user.get('PermissionsBoundary')!r}"
    )

    # positive control: the identical call with a real managed policy ARN succeeds
    iam.put_user_permissions_boundary(UserName=user_name, PermissionsBoundary=_VALID_BOUNDARY_ARN)
    user2 = iam.get_user(UserName=user_name)["User"]
    actual_boundary_arn = user2["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert actual_boundary_arn == _VALID_BOUNDARY_ARN, (
        f"expected PermissionsBoundaryArn {_VALID_BOUNDARY_ARN!r}, got {actual_boundary_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
