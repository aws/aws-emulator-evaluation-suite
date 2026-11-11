"""update-user-attributes."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-user-attributes"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUser renames/repaths a user; the new identity is visible via GetUser with the same
    UserId/CreateDate, and the old identity subsequently 404s with NoSuchEntity."""
    iam = ctx.client("iam")
    old_name = ctx.unique_name("sim2real-behav-user-old-")
    new_name = ctx.unique_name("sim2real-behav-user-new-")
    new_path = "/sim2real-updated/"

    created = iam.create_user(
        UserName=old_name,
        Tags=[{"Key": "sim2real", "Value": "update-user-attributes"}],
    )["User"]
    user_id = created["UserId"]
    create_date = created["CreateDate"]

    current_name = {"value": old_name}
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_user(UserName=current_name["value"])))

    before = iam.get_user(UserName=old_name)["User"]
    assert before["Path"] == "/", f"expected fresh user at root path, got {before['Path']!r}"

    iam.update_user(UserName=old_name, NewUserName=new_name, NewPath=new_path)
    current_name["value"] = new_name

    after = _poll_get_user(iam, new_name)
    assert after is not None, "renamed user never became visible under its new name"
    assert after["UserName"] == new_name, f"expected UserName {new_name!r}, got {after['UserName']!r}"
    assert after["Path"] == new_path, f"expected Path {new_path!r}, got {after['Path']!r}"
    assert after["UserId"] == user_id, f"UserId must stay stable across rename, expected {user_id!r}, got {after['UserId']!r}"
    assert after["CreateDate"] == create_date, (
        f"CreateDate must stay stable across rename, expected {create_date!r}, got {after['CreateDate']!r}"
    )
    expected_arn_suffix = f"{new_path}{new_name}"
    assert after["Arn"].endswith(expected_arn_suffix), f"expected Arn ending {expected_arn_suffix!r}, got {after['Arn']!r}"

    code, message = _error(lambda: iam.get_user(UserName=old_name))
    assert code == "NoSuchEntity", f"old user name should 404 after rename, got {code!r}"
    expected = f"The user with name {old_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    mutate_code, mutate_message = _error(
        lambda: iam.update_user(UserName=old_name, NewPath="/sim2real-dead/")
    )
    assert mutate_code == "NoSuchEntity", f"old user name should reject mutation after rename, got {mutate_code!r}"
    expected_mutate = f"The user with name {old_name} cannot be found."
    assert mutate_message == expected_mutate, (
        f"expected message {expected_mutate!r}, got {mutate_message!r}"
    )


def _safe(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_get_user(iam, user_name, timeout_s=15.0, interval_s=1.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return iam.get_user(UserName=user_name)["User"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
