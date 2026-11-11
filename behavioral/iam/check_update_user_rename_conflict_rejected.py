"""update-user-rename-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-rename-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateUser must reject renaming a user to a UserName that already exists,
    with EntityAlreadyExistsException, and leave both users' identities untouched;
    the identical call succeeds (positive control) once the target name is free."""
    iam = ctx.client("iam")
    user_a = ctx.unique_name("sim2real-behav-usr-a-")
    user_b = ctx.unique_name("sim2real-behav-usr-b-")

    created_a = iam.create_user(UserName=user_a)["User"]
    current_a = {"name": user_a}
    ctx.on_cleanup(lambda: _safe_delete(iam, current_a["name"]))
    created_b = iam.create_user(UserName=user_b)["User"]
    ctx.on_cleanup(lambda: _safe_delete(iam, user_b))

    err = _client_error(lambda: iam.update_user(UserName=user_a, NewUserName=user_b))
    # IAM's wire error code omits the "Exception" suffix present on the botocore
    # exception class name (the class is EntityAlreadyExistsException, but the
    # response Error.Code is "EntityAlreadyExists").
    assert err.get("Code") == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {err!r}"
    expected_msg = f"User with name {user_b} already exists."
    assert err.get("Message") == expected_msg, (err.get("Message"), expected_msg)

    # both original identities must still resolve untouched, by UserId/Arn — not
    # merely by the query's own UserName parameter echoing back.
    after_a = iam.get_user(UserName=user_a)["User"]
    assert after_a["UserId"] == created_a["UserId"], (after_a["UserId"], created_a["UserId"])
    assert after_a["Arn"] == created_a["Arn"], (after_a["Arn"], created_a["Arn"])
    after_b = iam.get_user(UserName=user_b)["User"]
    assert after_b["UserId"] == created_b["UserId"], (after_b["UserId"], created_b["UserId"])
    assert after_b["Arn"] == created_b["Arn"], (after_b["Arn"], created_b["Arn"])

    # positive control: renaming to a genuinely free name succeeds, and the old
    # name is released.
    free_name = ctx.unique_name("sim2real-behav-usr-free-")
    iam.update_user(UserName=user_a, NewUserName=free_name)
    current_a["name"] = free_name
    renamed = iam.get_user(UserName=free_name)["User"]
    assert renamed["UserId"] == created_a["UserId"], (renamed["UserId"], created_a["UserId"])
    stale = _client_error(lambda: iam.get_user(UserName=user_a))
    assert stale.get("Code") == "NoSuchEntity", f"expected NoSuchEntity, got {stale!r}"
    stale_msg = f"The user with name {user_a} cannot be found."
    assert stale.get("Message") == stale_msg, (stale.get("Message"), stale_msg)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete(iam, name):
    try:
        iam.delete_user(UserName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
