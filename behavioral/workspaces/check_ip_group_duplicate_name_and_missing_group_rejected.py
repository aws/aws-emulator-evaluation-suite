"""ip-group-duplicate-name-and-missing-group-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ip-group-duplicate-name-and-missing-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["workspaces"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIpGroup with a taken GroupName fails with ResourceAlreadyExistsException and DeleteIpGroup on
    an unknown or deleted GroupId with ResourceNotFoundException, each with the exact message and the
    real group intact; once it is deleted, the name can be created again.
    """
    ws = ctx.client("workspaces")
    name = ctx.unique_name("sim2real-wsipg-dup-")
    group_id = ws.create_ip_group(GroupName=name, GroupDesc="sim2real dup test")["GroupId"]
    live_group_id = [group_id]
    ctx.on_cleanup(lambda: _safe_delete_ip_group(ctx, live_group_id[0]))

    # Break #1: duplicate name is rejected, and no second group is created.
    err = _client_error(lambda: ws.create_ip_group(GroupName=name, GroupDesc="duplicate"))
    assert err["Code"] == "ResourceAlreadyExistsException", f"unexpected code: {err['Code']}"
    expected = (
        "Encountered an exception while creating IP Group - group already exists for given "
        f"group name - {name}"
    )
    assert err.get("Message") == expected, f"unexpected message: {err.get('Message')!r}"

    matches = [g for g in ws.describe_ip_groups().get("Result", []) if g.get("groupName") == name]
    assert len(matches) == 1 and matches[0]["groupId"] == group_id, (
        f"expected exactly the original group to exist, got {matches}"
    )

    # Break #2: deleting a nonexistent (but well-formed) GroupId is rejected, and the real
    # group is untouched.
    bogus_group_id = "wsipg-00000000"
    err = _client_error(lambda: ws.delete_ip_group(GroupId=bogus_group_id))
    assert err["Code"] == "ResourceNotFoundException", f"unexpected code: {err['Code']}"
    assert err.get("Message") == "Ip Group Id is not found.", f"unexpected message: {err.get('Message')!r}"

    still_present = ws.describe_ip_groups(GroupIds=[group_id])["Result"]
    assert len(still_present) == 1, f"real group disappeared after the bogus delete: {still_present}"

    # Positive control: deleting the real group works.
    ws.delete_ip_group(GroupId=group_id)
    remaining = ws.describe_ip_groups(GroupIds=[group_id])["Result"]
    assert remaining == [], f"group still present after a real delete: {remaining}"

    # The dead GroupId stays dead: a mutation on it still 404s, it doesn't silently no-op.
    err = _client_error(lambda: ws.delete_ip_group(GroupId=group_id))
    assert err["Code"] == "ResourceNotFoundException", (
        f"deleting an already-deleted group should still 404, got {err['Code']}"
    )
    assert err.get("Message") == "Ip Group Id is not found.", f"unexpected message: {err.get('Message')!r}"

    # Restore leg: the name conflict was state (the original group), not the input itself. With
    # that group gone, the identical create call now succeeds and the name is reusable.
    new_group_id = ws.create_ip_group(GroupName=name, GroupDesc="sim2real dup test - restored")[
        "GroupId"
    ]
    live_group_id[0] = new_group_id
    restored = [g for g in ws.describe_ip_groups().get("Result", []) if g.get("groupName") == name]
    assert len(restored) == 1 and restored[0]["groupId"] == new_group_id, (
        f"expected the recreated group to be the sole holder of the name, got {restored}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded with: {result}")


def _safe_delete_ip_group(ctx, group_id: str) -> None:
    from botocore.exceptions import ClientError

    ws = ctx.client("workspaces")
    try:
        ws.delete_ip_group(GroupId=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
