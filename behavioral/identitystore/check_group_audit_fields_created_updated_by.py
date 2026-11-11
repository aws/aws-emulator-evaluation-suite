"""group-audit-fields-created-updated-by."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "group-audit-fields-created-updated-by"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DescribeGroup populates CreatedBy/UpdatedBy identity attribution; UpdatedAt advances past
    CreatedAt after a mutation while CreatedAt itself never changes."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-behav-audit-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    before = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert before.get("CreatedBy"), f"expected CreatedBy populated on create, got {before.get('CreatedBy')!r}"
    assert before.get("UpdatedBy"), f"expected UpdatedBy populated on create, got {before.get('UpdatedBy')!r}"
    created_at = before["CreatedAt"]
    updated_at_before = before["UpdatedAt"]

    idstore.update_group(
        IdentityStoreId=store_id,
        GroupId=group_id,
        Operations=[{"AttributePath": "description", "AttributeValue": "audit-field-check"}],
    )

    after = _poll_until_updated_at_advances(idstore, store_id, group_id, updated_at_before)
    assert after.get("CreatedBy"), f"expected CreatedBy populated after update, got {after.get('CreatedBy')!r}"
    assert after.get("UpdatedBy"), f"expected UpdatedBy populated after update, got {after.get('UpdatedBy')!r}"
    assert after["CreatedAt"] == created_at, (
        f"expected CreatedAt to stay {created_at!r} across an update, got {after['CreatedAt']!r}"
    )
    assert after["UpdatedAt"] > updated_at_before, (
        f"expected UpdatedAt to advance past its pre-update value {updated_at_before!r}, "
        f"got {after['UpdatedAt']!r}"
    )


from botocore.exceptions import ClientError


def _poll_until_updated_at_advances(idstore, store_id, group_id, updated_at_before):
    deadline = time.monotonic() + 30
    latest = None
    while time.monotonic() < deadline:
        latest = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
        if latest["UpdatedAt"] > updated_at_before:
            return latest
        time.sleep(2)
    raise AssertionError(
        f"UpdatedAt did not advance past its pre-update value {updated_at_before!r} within 30s "
        f"of UpdateGroup; last observed UpdatedAt={latest['UpdatedAt']!r}"
    )


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


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
