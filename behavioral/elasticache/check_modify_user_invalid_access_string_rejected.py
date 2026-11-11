"""modify-user-invalid-access-string-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-user-invalid-access-string-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyUser with a syntactically malformed Redis ACL access string is rejected
    with InvalidParameterValue and the user's access string is left untouched, never
    partially applied."""
    ec = ctx.client("elasticache")
    user_id = ctx.unique_name("sim2real-ecuser-")
    original_access = "off -@all"

    ec.create_user(
        UserId=user_id,
        UserName=user_id,
        Engine="redis",
        AccessString=original_access,
        NoPasswordRequired=True,
        Tags=[{"Key": "sim2real", "Value": user_id}],
    )
    ctx.on_cleanup(lambda: _delete_user(ctx, user_id))
    _wait_for_user_status(ctx, user_id, {"active"}, timeout_s=60)

    malformed_access = "on ~* &*&*&* not-a-real-acl-token %%%garbage%%%"

    def _modify_bad():
        ec.modify_user(UserId=user_id, AccessString=malformed_access)

    code, message = _error(_modify_bad)
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "The access-string is invalid.", f"unexpected InvalidParameterValue message: {message!r}"

    # effect absent: access string unchanged, no partial application
    users = ec.describe_users(UserId=user_id)["Users"]
    assert users[0]["AccessString"] == original_access, (
        f"access string mutated despite rejection: {users[0]['AccessString']!r}"
    )

    # positive control: a syntactically valid access string change succeeds
    valid_access = "on ~* +@all"
    ec.modify_user(UserId=user_id, AccessString=valid_access)
    final_access = _wait_for_user_access_string(ctx, user_id, valid_access, timeout_s=60)
    assert final_access == valid_access, (
        f"expected access string {valid_access!r} after the accepted ModifyUser, got {final_access!r}"
    )

    # deletes prove gone and unusable: delete, an independent read confirms the specific
    # not-found code, and a mutation on the dead id also fails with that same code.
    ec.delete_user(UserId=user_id)
    not_found_message = f"User {user_id} not found."
    deleted_code, deleted_message = _wait_for_user_deleted(ctx, user_id, timeout_s=240)
    assert deleted_code == "UserNotFound", (
        f"expected UserNotFound reading the deleted user, got {deleted_code}"
    )
    assert deleted_message == not_found_message, (
        f"unexpected UserNotFound message reading the deleted user: {deleted_message!r}"
    )
    modify_dead_code, modify_dead_message = _error(
        lambda: ec.modify_user(UserId=user_id, AccessString=valid_access)
    )
    assert modify_dead_code == "UserNotFound", (
        f"expected UserNotFound modifying the deleted user, got {modify_dead_code}"
    )
    assert modify_dead_message == not_found_message, (
        f"unexpected UserNotFound message modifying the deleted user: {modify_dead_message!r}"
    )


# ===== helpers =====

def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _wait_for_user_status(ctx, user_id, target_statuses, timeout_s=60.0, interval_s=3.0):
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        users = ec.describe_users(UserId=user_id)["Users"]
        if users:
            status = users[0]["Status"]
            if status in target_statuses:
                return status
        time.sleep(interval_s)
    raise AssertionError(f"user {user_id} never reached {target_statuses}, last status={status}")


def _wait_for_user_access_string(ctx, user_id, expected_access, timeout_s=60.0, interval_s=3.0):
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    access = None
    while time.monotonic() < deadline:
        users = ec.describe_users(UserId=user_id)["Users"]
        if users and users[0]["Status"] == "active":
            access = users[0]["AccessString"]
            if access == expected_access:
                return access
        time.sleep(interval_s)
    raise AssertionError(f"user {user_id} access string never became {expected_access!r}, last={access!r}")


def _wait_for_user_deleted(ctx, user_id, timeout_s=60.0, interval_s=3.0):
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            ec.describe_users(UserId=user_id)
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code == "UserNotFound":
                return last_code, e.response["Error"].get("Message")
            raise
        time.sleep(interval_s)
    raise AssertionError(f"user {user_id} still describable after {timeout_s}s (last_code={last_code})")


def _delete_user(ctx, user_id):
    """Delete the user; one still modifying (InvalidUserState) is retried for up to 60 s."""
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + 60
    while True:
        try:
            ec.delete_user(UserId=user_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "UserNotFound":
                return
            if code != "InvalidUserState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
