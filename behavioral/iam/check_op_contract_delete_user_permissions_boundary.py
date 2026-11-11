"""op-contract-deleteUserPermissionsBoundary."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deleteUserPermissionsBoundary"
GROUP = "error-semantics"
SERVICES = ["iam"]

_BOUNDARY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUserPermissionsBoundary clears a permissions boundary set at creation; the same
    call against a nonexistent user is rejected with NoSuchEntityException."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name, PermissionsBoundary=_BOUNDARY_ARN)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    before = iam.get_user(UserName=user_name)["User"]
    before_arn = before["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert before_arn == _BOUNDARY_ARN, f"expected boundary {_BOUNDARY_ARN}, got {before_arn}"

    # success path
    resp = iam.delete_user_permissions_boundary(UserName=user_name)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from DeleteUserPermissionsBoundary, got {status}"

    after = iam.get_user(UserName=user_name)["User"]
    assert "PermissionsBoundary" not in after, "permissions boundary still present after delete"

    # error boundary: target user does not exist
    missing_user = ctx.unique_name("sim2real-nouser-")
    code, message = _error(lambda: iam.delete_user_permissions_boundary(UserName=missing_user))
    # IAM's error Code is the bare name ("NoSuchEntity"), not the botocore exception
    # class name ("NoSuchEntityException").
    assert code == "NoSuchEntity", f"expected NoSuchEntity for missing user, got {code}"
    expected = f"User {missing_user} was not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
