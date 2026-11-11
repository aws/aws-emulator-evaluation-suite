"""update-group-name."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-group-name"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup renames/repaths a group; the new identity is visible via GetGroup with the
    same GroupId/CreateDate, and the old name subsequently 404s with NoSuchEntity."""
    iam = ctx.client("iam")
    old_name = ctx.unique_name("sim2real-behav-group-old-")
    new_name = ctx.unique_name("sim2real-behav-group-new-")
    new_path = "/sim2real-updated/"

    created = iam.create_group(GroupName=old_name)["Group"]
    group_id = created["GroupId"]
    create_date = created["CreateDate"]

    current_name = {"value": old_name}
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_group(GroupName=current_name["value"])))

    before = iam.get_group(GroupName=old_name)["Group"]
    assert before["Path"] == "/", f"expected default path '/', got {before['Path']!r}"

    iam.update_group(GroupName=old_name, NewGroupName=new_name, NewPath=new_path)
    current_name["value"] = new_name

    after = _poll_get_group(iam, new_name)
    assert after is not None, "renamed group never became visible under its new name"
    assert after["GroupName"] == new_name, f"expected GroupName {new_name!r}, got {after['GroupName']!r}"
    assert after["Path"] == new_path, f"expected Path {new_path!r}, got {after['Path']!r}"
    assert after["GroupId"] == group_id, f"GroupId changed across rename: expected {group_id!r}, got {after['GroupId']!r}"
    assert after["CreateDate"] == create_date, (
        f"CreateDate changed across rename: expected {create_date!r}, got {after['CreateDate']!r}"
    )
    assert after["Arn"].endswith(f"{new_path}{new_name}"), (
        f"expected Arn to end with {new_path}{new_name!r}, got {after['Arn']!r}"
    )

    code, message = _error(lambda: iam.get_group(GroupName=old_name))
    assert code == "NoSuchEntity", f"old group name should 404 after rename, got {code!r}"
    expected = f"The group with name {old_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _poll_get_group(iam, group_name, timeout_s=15.0, interval_s=1.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return iam.get_group(GroupName=group_name)["Group"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
