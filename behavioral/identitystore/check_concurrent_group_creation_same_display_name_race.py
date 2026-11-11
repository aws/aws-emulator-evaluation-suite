"""concurrent-group-creation-same-display-name-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-group-creation-same-display-name-race"
GROUP = "concurrency"
SERVICES = ["identitystore"]


# A losing racer's ConflictException carries one of these two exact messages, depending on where
# it collides with the winner.
_CONFLICT_MESSAGES = ("Duplicate GroupDisplayName", "Group updated by another request")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Racing CreateGroup with the identical DisplayName yields exactly one winner; every loser
    fails with ConflictException and one of its two exact messages, and GetGroupId resolves the
    name to the winner."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-idstore-group-race-")

    def attempt():
        try:
            resp = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)
            return ("ok", resp["GroupId"])
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    racers = 6
    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(attempt) for _ in range(racers)]
        outcomes = [f.result() for f in as_completed(futures)]

    successes = [v for kind, v in outcomes if kind == "ok"]
    errors = [v[0] for kind, v in outcomes if kind == "error"]
    messages = [v[1] for kind, v in outcomes if kind == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {successes}"
    assert len(errors) == racers - 1, f"expected {racers - 1} losers, got {len(errors)}: {errors}"
    assert all(code == "ConflictException" for code in errors), f"expected all losers to be ConflictException, got {errors}"
    assert all(message in _CONFLICT_MESSAGES for message in messages), (
        f"expected every loser's message to be one of {_CONFLICT_MESSAGES}, got {messages}"
    )

    winner_group_id = successes[0]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, winner_group_id))

    resolved = idc.get_group_id(
        IdentityStoreId=identity_store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": display_name}},
    )["GroupId"]
    assert resolved == winner_group_id, f"expected get_group_id to resolve to the winner {winner_group_id}, got {resolved}"


def _get_identity_store_id(ctx) -> str:
    import time

    sso_admin = ctx.client("sso-admin")

    def _ready_id(insts):
        for inst in insts:
            if inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        return None

    instances = sso_admin.list_instances().get("Instances", [])
    found = _ready_id(instances)
    if found:
        return found
    if not instances:
        try:
            sso_admin.create_instance(Name="sim2real-idstore-group-race")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
    deadline = time.time() + 180
    while time.time() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        time.sleep(3)
    raise AssertionError(
        "No IAM Identity Center instance could be enabled in this account/region "
        "(sso-admin CreateInstance/ListInstances never surfaced an IdentityStoreId "
        "within 180s)."
    )


def _safe_delete_group(ctx, identity_store_id: str, group_id: str) -> None:
    idc = ctx.client("identitystore")
    try:
        idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
