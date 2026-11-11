"""delete-already-deleted-group-is-idempotent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-already-deleted-group-is-idempotent"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A second DeleteGroup on an already-deleted group succeeds (no error, no resurrection)."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")

    name_a = ctx.unique_name("sim2real-idstore-group-a-")
    group_a_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=name_a)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_a_id)))

    # First delete succeeds (this IS the control for DeleteGroup on a live resource).
    idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_a_id)

    # Second delete of the same, now-gone, group is idempotent (no error): DeleteGroup on
    # AWS empirically does not resurface ResourceNotFoundException for a repeat delete.
    idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_a_id)

    # Effect absent: the group is still gone, no resurrection or partial state. Deletion may
    # take a moment to fully propagate; poll to a bounded deadline.
    describe_err = _poll_error(
        lambda: idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_a_id)
    )
    assert describe_err == ("ResourceNotFoundException", "Group not found"), (
        f"expected DescribeGroup on the deleted group to keep 404ing with ResourceNotFoundException "
        f"'Group not found', got {describe_err!r}"
    )

    # A mutation on the dead id also fails specifically: the repeat DeleteGroup being accepted
    # does not mean identitystore silently accepts other operations against the gone GroupId.
    update_err = _error(
        lambda: idc.update_group(
            IdentityStoreId=identity_store_id,
            GroupId=group_a_id,
            Operations=[{"AttributePath": "displayName", "AttributeValue": "sim2real-resurrected"}],
        )
    )
    assert update_err == ("ResourceNotFoundException", "Group not found"), (
        f"expected UpdateGroup on the deleted group to fail with ResourceNotFoundException "
        f"'Group not found', got {update_err!r}"
    )

    # Positive control: DeleteGroup on a different, unrelated, live group still succeeds.
    name_b = ctx.unique_name("sim2real-idstore-group-b-")
    group_b_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=name_b)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_b_id)))
    idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_b_id)
    final_err = _error(lambda: idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_b_id))
    assert final_err == ("ResourceNotFoundException", "Group not found"), (
        f"expected DescribeGroup on the freshly-deleted control group to be ResourceNotFoundException "
        f"'Group not found', got {final_err!r}"
    )


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
    raise AssertionError("no IAM Identity Center instance could be enabled in this account/region")


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_error(fn, timeout_s=60):
    """Call fn() until it raises ResourceNotFoundException; return that ClientError (code,
    message). A success or any other refusal keeps polling until the deadline, then the last
    outcome raises, so a delete that never takes effect fails loudly."""
    import time as _poll_time

    deadline = _poll_time.time() + timeout_s
    while True:
        try:
            last = ("SUCCEEDED", fn())
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return err["Code"], err.get("Message")
            last = (err["Code"], err.get("Message"))
        if _poll_time.time() >= deadline:
            raise AssertionError(
                f"expected ResourceNotFoundException within {timeout_s}s, last outcome {last!r}"
            )
        _poll_time.sleep(3)


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
