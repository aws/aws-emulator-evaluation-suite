"""input-security-group-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "input-security-group-lifecycle"
GROUP = "resource-lifecycle"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/Update/DeleteInputSecurityGroup round-trip the group's allowed CIDR rules."""
    medialive = ctx.client("medialive")
    group = medialive.create_input_security_group(
        WhitelistRules=[{"Cidr": "203.0.113.0/24"}],
        Tags={"sim2real-env": "test", "sim2real-owner": "behavioral"},
    )["SecurityGroup"]
    group_id = group["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_input_security_group(InputSecurityGroupId=group_id)))
    assert group["State"] == "IDLE", f"expected IDLE right after create, got {group['State']!r}"
    created_cidrs = [r["Cidr"] for r in group["WhitelistRules"]]
    assert created_cidrs == ["203.0.113.0/24"], f"expected whitelist ['203.0.113.0/24'], got {created_cidrs!r}"

    medialive.update_input_security_group(
        InputSecurityGroupId=group_id, WhitelistRules=[{"Cidr": "198.51.100.0/24"}, {"Cidr": "192.0.2.0/24"}]
    )
    described = medialive.describe_input_security_group(InputSecurityGroupId=group_id)
    cidrs = sorted(r["Cidr"] for r in described["WhitelistRules"])
    assert cidrs == ["192.0.2.0/24", "198.51.100.0/24"], f"expected updated whitelist after replace, got {cidrs!r}"

    medialive.delete_input_security_group(InputSecurityGroupId=group_id)
    final = _wait_for_deleted(ctx, lambda: medialive.describe_input_security_group(InputSecurityGroupId=group_id))
    groups_after = medialive.list_input_security_groups()["InputSecurityGroups"]
    assert group_id not in {g["Id"] for g in groups_after}, (
        f"deleted group {group_id} (terminal={final!r}) still present in list_input_security_groups"
    )

    def _update():
        return medialive.update_input_security_group(
            InputSecurityGroupId=group_id, WhitelistRules=[{"Cidr": "192.0.2.0/24"}]
        )

    if final == "NotFoundException":
        # Hard-deleted: the id is fully gone, so a mutation on it must 404 too, with the message
        # AWS gives for an InputSecurityGroup id it does not know.
        code, message = _client_error(_update, "UpdateInputSecurityGroup on a hard-deleted group")
        assert code == "NotFoundException", f"expected NotFoundException mutating a hard-deleted group, got {code!r}"
        assert message == f"InputSecurityGroup {group_id} not found", message
    else:
        # MediaLive soft-deletes InputSecurityGroup: the id stays individually addressable
        # and mutable in state DELETED (confirmed on real AWS) even though it is already
        # excluded from list_input_security_groups above.
        _update()
        tombstone = medialive.describe_input_security_group(InputSecurityGroupId=group_id)
        tombstone_cidrs = [r["Cidr"] for r in tombstone["WhitelistRules"]]
        assert tombstone_cidrs == ["192.0.2.0/24"], (
            f"expected the DELETED tombstone to reflect the update that just succeeded, got {tombstone_cidrs!r}"
        )


def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded: {result!r}")


def _wait_for_deleted(ctx, describe_fn, timeout_s=120.0, interval_s=5.0):
    """Poll until the resource either 404s or settles into a terminal DELETED state."""
    from botocore.exceptions import ClientError
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = describe_fn()
            last = resp.get("State")
            if last == "DELETED":
                return "DELETED"
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return "NotFoundException"
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"resource never reached a deleted terminal state within {timeout_s}s, last={last!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
