"""recreate-group-after-delete-with-same-displayname."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "recreate-group-after-delete-with-same-displayname"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A DisplayName's uniqueness claim is released on DeleteGroup: CreateGroup with the same
    DisplayName afterward succeeds (rather than being permanently reserved)."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    display_name = ctx.unique_name("sim2real-behav-recreate-group-")
    first_group_id = idstore.create_group(IdentityStoreId=store_id, DisplayName=display_name)["GroupId"]
    idstore.delete_group(IdentityStoreId=store_id, GroupId=first_group_id)

    # Deletion of the uniqueness claim may lag briefly behind the DeleteGroup call;
    # poll a bounded window for CreateGroup with the same name to succeed.
    second_group_id = None
    last_code = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            second_group_id = idstore.create_group(IdentityStoreId=store_id, DisplayName=display_name)["GroupId"]
            break
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "ConflictException":
                raise
            time.sleep(3)

    assert second_group_id is not None, f"recreate never succeeded; last error was {last_code}"
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=second_group_id))
    )
    assert second_group_id != first_group_id

    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=second_group_id)
    assert described["DisplayName"] == display_name

    # The old GroupId is truly gone (not merely superseded).
    old_code, old_message = _client_error(lambda: idstore.describe_group(IdentityStoreId=store_id, GroupId=first_group_id))
    assert old_code == "ResourceNotFoundException"
    assert old_message == "Group not found", (
        f"expected AWS's exact ResourceNotFoundException message, got {old_message!r}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
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
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        time.sleep(3)
    raise AssertionError(
        "no IAM Identity Center instance could be enabled in this account/region"
    )


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
