"""update-user-rename."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-rename"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUser renaming/re-pathing a user updates its ARN, keeps its UserId
    stable, and the user remains retrievable only under its new identity."""
    iam = ctx.client("iam")
    old_name = ctx.unique_name("sim2real-behav-usr-old-")
    new_name = ctx.unique_name("sim2real-behav-usr-new-")
    old_path = "/"
    new_path = "/sim2real-renamed/"

    created = iam.create_user(
        UserName=old_name, Path=old_path, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )["User"]

    active_name = {"name": old_name}

    def _cleanup():
        try:
            iam.delete_user(UserName=active_name["name"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    old_arn = created["Arn"]
    create_date = created["CreateDate"]
    assert old_arn.endswith(f":user{old_path}{old_name}"), (
        f"expected ARN ending with :user{old_path}{old_name}, got {old_arn}"
    )

    iam.update_user(UserName=old_name, NewUserName=new_name, NewPath=new_path)
    active_name["name"] = new_name  # cleanup must now target the renamed user

    user = _poll_until(
        lambda: _get_user_or_none(iam, new_name),
        lambda u: u is not None,
        timeout_s=20.0,
    )
    assert user["UserName"] == new_name, f"expected UserName {new_name}, got {user['UserName']}"
    assert user["Path"] == new_path, f"expected Path {new_path}, got {user['Path']}"
    assert user["UserId"] == created["UserId"], "UserId must stay stable across rename"
    assert user["CreateDate"] == create_date, (
        f"expected CreateDate to stay stable across rename, got {user['CreateDate']} "
        f"(was {create_date})"
    )
    assert user["Arn"] != old_arn, f"Arn must change after rename, still {old_arn}"
    assert user["Arn"].endswith(f":user{new_path}{new_name}"), (
        f"expected ARN ending with :user{new_path}{new_name}, got {user['Arn']}"
    )

    # old identity must be gone: an independent read AND a mutation both refuse it
    read_code, read_message = _error(lambda: iam.get_user(UserName=old_name))
    assert read_code == "NoSuchEntity", (
        f"old name must 404 with NoSuchEntity on GetUser after rename, got {read_code}"
    )
    expected_read = f"The user with name {old_name} cannot be found."
    assert read_message == expected_read, f"expected message {expected_read!r}, got {read_message!r}"
    dead_mutation_code, dead_mutation_message = _error(
        lambda: iam.update_user(UserName=old_name, NewPath="/sim2real-dead/")
    )
    assert dead_mutation_code == "NoSuchEntity", (
        f"a mutation against the dead old name must also refuse with NoSuchEntity, "
        f"got {dead_mutation_code}"
    )
    expected_mutate = f"The user with name {old_name} cannot be found."
    assert dead_mutation_message == expected_mutate, (
        f"expected message {expected_mutate!r}, got {dead_mutation_message!r}"
    )


def _get_user_or_none(iam, name):
    try:
        return iam.get_user(UserName=name)["User"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=20.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError(f"condition not observed within {timeout_s}s; last saw {result!r}")
    return result


def _error(fn):
    """Call fn(); return the botocore (Code, Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
