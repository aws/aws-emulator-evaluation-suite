"""create-user-permissions-boundary-nonexistent-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-permissions-boundary-nonexistent-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]

_VALID_BOUNDARY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUser with a PermissionsBoundary ARN that names no policy is refused atomically --
    no user is created -- while the identical call with a real managed policy succeeds."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    rejected_name = ctx.unique_name("sim2real-cupb-reject-")
    bogus_arn = f"arn:aws:iam::{account}:policy/sim2real-missing-{rejected_name}"
    code, message = _error(
        lambda: iam.create_user(UserName=rejected_name, PermissionsBoundary=bogus_arn)
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent boundary ARN, got {code!r}: {message!r}"
    expected = f"Scope ARN: {bogus_arn} does not exist or is not attachable."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the rejected create must have produced no user at all, not merely one without a boundary
    leak_code, _ = _error(lambda: iam.get_user(UserName=rejected_name))
    assert leak_code == "NoSuchEntity", (
        f"expected the rejected CreateUser to have created no user, but GetUser returned {leak_code!r}"
    )

    # positive control: the identical shape of call with a real managed-policy ARN succeeds
    accepted_name = ctx.unique_name("sim2real-cupb-accept-")
    iam.create_user(UserName=accepted_name, PermissionsBoundary=_VALID_BOUNDARY_ARN)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=accepted_name))

    user = iam.get_user(UserName=accepted_name)["User"]
    actual_boundary = user["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert actual_boundary == _VALID_BOUNDARY_ARN, (
        f"expected the inline boundary {_VALID_BOUNDARY_ARN!r} reflected on GetUser, got {actual_boundary!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
