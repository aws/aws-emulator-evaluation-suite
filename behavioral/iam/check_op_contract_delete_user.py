"""op-contract-deleteUser."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteUser"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUser removes an unencumbered user; DeleteConflict while an access key remains, the
    user survives that conflict, and the identical call succeeds once the key is removed."""
    iam = ctx.client("iam")

    # success path
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name)
    resp = iam.delete_user(UserName=user_name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    code, code_msg = _client_error(lambda: iam.get_user(UserName=user_name))
    assert code == "NoSuchEntity", f"expected user gone, got {code}"
    assert code_msg == f"The user with name {user_name} cannot be found.", f"unexpected error message {code_msg!r}"

    # error boundary: user still has an access key -> DeleteConflictException
    conflict_user = ctx.unique_name("sim2real-behav-user-conflict-")
    iam.create_user(UserName=conflict_user)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_user(UserName=conflict_user)))
    key = iam.create_access_key(UserName=conflict_user)["AccessKey"]
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_access_key(UserName=conflict_user, AccessKeyId=key["AccessKeyId"]))
    )

    conflict_code, conflict_code_msg = _client_error(lambda: iam.delete_user(UserName=conflict_user))
    assert conflict_code == "DeleteConflict", f"expected DeleteConflict, got {conflict_code}"
    assert conflict_code_msg == "Cannot delete entity, must delete access keys first.", f"unexpected error message {conflict_code_msg!r}"

    # effect-absent: the rejected delete did not go through
    survives = iam.get_user(UserName=conflict_user)["User"]["UserName"]
    assert survives == conflict_user, f"user should survive a DeleteConflict, got {survives!r}"

    # restore: remove the blocking key, then the identical call must now succeed
    iam.delete_access_key(UserName=conflict_user, AccessKeyId=key["AccessKeyId"])
    resp2 = iam.delete_user(UserName=conflict_user)
    assert resp2["ResponseMetadata"]["HTTPStatusCode"] == 200
    code2, code2_msg = _client_error(lambda: iam.get_user(UserName=conflict_user))
    assert code2 == "NoSuchEntity", f"expected user gone after restore, got {code2}"
    assert code2_msg == f"The user with name {conflict_user} cannot be found.", f"unexpected error message {code2_msg!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
