"""update-user-rename-carries-access-keys-and-group-membership."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-rename-carries-access-keys-and-group-membership"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUser renames the same principal: its access key and group membership carry over to the
    new name without re-issue or re-add, and the old name fails with NoSuchEntity.
    """
    iam = ctx.client("iam")
    old_name = ctx.unique_name("sim2real-behav-usr-old-")
    new_name = ctx.unique_name("sim2real-behav-usr-new-")
    group_name = ctx.unique_name("sim2real-behav-grp-")

    iam.create_user(UserName=old_name, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    active_name = {"name": old_name}

    def _cleanup_user():
        try:
            iam.delete_user(UserName=active_name["name"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_user)

    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    access_key_id = iam.create_access_key(UserName=old_name)["AccessKey"]["AccessKeyId"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=active_name["name"], AccessKeyId=access_key_id)
    )

    iam.add_user_to_group(GroupName=group_name, UserName=old_name)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: iam.remove_user_from_group(
                GroupName=group_name, UserName=active_name["name"]
            )
        )
    )

    iam.update_user(UserName=old_name, NewUserName=new_name)
    active_name["name"] = new_name  # cleanup must now target the renamed user

    renamed_user = _poll_until(
        lambda: _get_user_or_none(iam, new_name),
        lambda u: u is not None,
        timeout_s=20.0,
    )
    assert renamed_user["UserName"] == new_name, (
        f"expected UserName {new_name!r} after rename, got {renamed_user['UserName']!r}"
    )

    # --- The access key followed the rename: same key id, now reporting the new owner.
    keys_under_new = iam.list_access_keys(UserName=new_name)["AccessKeyMetadata"]
    assert [k["AccessKeyId"] for k in keys_under_new] == [access_key_id], (
        f"expected exactly the pre-rename access key {access_key_id!r} under the new name, "
        f"got {[k['AccessKeyId'] for k in keys_under_new]!r}"
    )
    assert keys_under_new[0]["UserName"] == new_name, (
        f"expected the access key's UserName to report the renamed principal {new_name!r}, "
        f"got {keys_under_new[0]['UserName']!r}"
    )
    old_name_keys_code, old_name_keys_msg = _error(lambda: iam.list_access_keys(UserName=old_name))
    assert old_name_keys_code == "NoSuchEntity", (
        f"expected ListAccessKeys(UserName={old_name!r}) to 404 with NoSuchEntity after rename, "
        f"got {old_name_keys_code!r}"
    )
    expected = f"The user with name {old_name} cannot be found."
    assert old_name_keys_msg == expected, f"expected message {expected!r}, got {old_name_keys_msg!r}"

    # --- The group membership followed the rename too: GetGroup lists only the new name.
    group_members = [u["UserName"] for u in iam.get_group(GroupName=group_name)["Users"]]
    assert group_members == [new_name], (
        f"expected GetGroup({group_name!r}) to list exactly the renamed user {new_name!r}, "
        f"got {group_members!r}"
    )
    groups_for_new = [
        g["GroupName"] for g in iam.list_groups_for_user(UserName=new_name)["Groups"]
    ]
    assert group_name in groups_for_new, (
        f"expected ListGroupsForUser({new_name!r}) to include {group_name!r}, "
        f"got {groups_for_new!r}"
    )
    old_name_groups_code, old_name_groups_msg = _error(
        lambda: iam.list_groups_for_user(UserName=old_name))
    assert old_name_groups_code == "NoSuchEntity", (
        f"expected ListGroupsForUser(UserName={old_name!r}) to 404 with NoSuchEntity after "
        f"rename, got {old_name_groups_code!r}"
    )
    expected = f"The user with name {old_name} cannot be found."
    assert old_name_groups_msg == expected, (
        f"expected message {expected!r}, got {old_name_groups_msg!r}")


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
    """(code, message) of the ClientError fn() raises; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
