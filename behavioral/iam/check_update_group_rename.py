"""update-group-rename."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-group-rename"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup renaming/re-pathing a group updates its ARN, keeps its GroupId
    stable, and the group remains retrievable only under its new identity."""
    iam = ctx.client("iam")
    old_name = ctx.unique_name("sim2real-behav-grp-old-")
    new_name = ctx.unique_name("sim2real-behav-grp-new-")
    old_path = "/"
    new_path = "/sim2real-renamed/"

    created = iam.create_group(GroupName=old_name, Path=old_path)["Group"]

    active_name = {"name": old_name}

    def _cleanup():
        try:
            iam.delete_group(GroupName=active_name["name"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    old_arn = created["Arn"]
    assert old_arn.endswith(f":group{old_path}{old_name}"), old_arn

    iam.update_group(GroupName=old_name, NewGroupName=new_name, NewPath=new_path)
    active_name["name"] = new_name  # cleanup must now target the renamed group

    group = _poll_until(
        lambda: _get_group_or_none(iam, new_name),
        lambda g: g is not None,
        timeout_s=20.0,
    )
    assert group is not None, "renamed group never became retrievable under new name"
    assert group["GroupName"] == new_name, f"expected GroupName {new_name!r}, got {group['GroupName']!r}"
    assert group["Path"] == new_path, f"expected Path {new_path!r}, got {group['Path']!r}"
    assert group["GroupId"] == created["GroupId"], "GroupId must stay stable across rename"
    assert group["Arn"] != old_arn, f"Arn must change after rename, still {old_arn!r}"
    assert group["Arn"].endswith(f":group{new_path}{new_name}"), group["Arn"]

    # old identity must be gone: an independent read 404s, and a mutation on the dead id also fails
    old_read_code, old_read_message = _error(lambda: iam.get_group(GroupName=old_name))
    assert old_read_code == "NoSuchEntity", f"expected NoSuchEntity reading old name, got {old_read_code!r}"
    expected_read = f"The group with name {old_name} cannot be found."
    assert old_read_message == expected_read, (
        f"expected message {expected_read!r}, got {old_read_message!r}"
    )

    old_mutate_code, old_mutate_message = _error(
        lambda: iam.update_group(GroupName=old_name, NewGroupName=old_name)
    )
    assert old_mutate_code == "NoSuchEntity", (
        f"expected NoSuchEntity mutating dead old name, got {old_mutate_code!r}"
    )
    expected_mutate = f"The group with name {old_name} cannot be found."
    assert old_mutate_message == expected_mutate, (
        f"expected message {expected_mutate!r}, got {old_mutate_message!r}"
    )


def _get_group_or_none(iam, name):
    try:
        return iam.get_group(GroupName=name)["Group"]
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
    return result


def _error(fn):
    """Call fn(); return the botocore (Code, Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
