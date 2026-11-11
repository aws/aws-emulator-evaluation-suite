"""concurrent-duplicate-group-displayname-single-winner."""
from __future__ import annotations

import threading

from behavioral_harness import tags

CHECK = "concurrent-duplicate-group-displayname-single-winner"
GROUP = "concurrency"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Racing CreateGroup with an identical DisplayName yields exactly one surviving group."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-behav-race-group-")

    n_racers = 6
    successes = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_racers)

    def racer():
        barrier.wait()
        try:
            resp = idstore.create_group(IdentityStoreId=store_id, DisplayName=display_name)
            with lock:
                successes.append(resp["GroupId"])
        except Exception as exc:  # noqa: BLE001 - classify below
            with lock:
                errors.append(_client_error_code(exc))

    threads = [threading.Thread(target=racer) for _ in range(n_racers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {successes}"
    assert len(errors) == n_racers - 1, f"expected {n_racers - 1} losers, got {len(errors)}: {errors}"
    # message varies: a losing racer gets either "Duplicate GroupDisplayName" or "Group updated by
    # another request", depending on where in the write it collides with the winner.
    assert all(code == "ConflictException" for code in errors), errors

    winning_group_id = successes[0]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=winning_group_id))
    )

    resolved = idstore.get_group_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": display_name}},
    )
    assert resolved["GroupId"] == winning_group_id, (
        f"expected the surviving group to resolve back to {winning_group_id}, got {resolved['GroupId']}"
    )

    idstore.delete_group(IdentityStoreId=store_id, GroupId=winning_group_id)
    describe_err = _error(
        lambda: idstore.describe_group(IdentityStoreId=store_id, GroupId=winning_group_id)
    )
    assert describe_err == ("ResourceNotFoundException", "Group not found"), (
        f"expected DescribeGroup on the deleted winner to 404, got {describe_err}"
    )
    update_err = _error(
        lambda: idstore.update_group(
            IdentityStoreId=store_id,
            GroupId=winning_group_id,
            Operations=[{"AttributePath": "displayName", "AttributeValue": ctx.unique_name("post-delete-")}],
        )
    )
    assert update_err == ("ResourceNotFoundException", "Group not found"), (
        f"expected UpdateGroup on the deleted winner to also fail not-found, got {update_err}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
    import time
    from botocore.exceptions import ClientError

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
            sso_admin.create_instance(Name="sim2real-behav-idc")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ConflictException",):
                raise
    deadline = time.time() + 180
    while time.time() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        time.sleep(3)
    raise AssertionError(
        "no IAM Identity Center instance could be enabled in this account/region"
    )


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error_code(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"non-ClientError:{type(exc).__name__}"


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call against the deleted group to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
