"""user-audit-fields-created-updated-by."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "user-audit-fields-created-updated-by"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DescribeUser populates CreatedBy/UpdatedBy identity attribution; UpdatedAt advances past
    CreatedAt after a mutation while CreatedAt itself never changes."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-audit-user-"),
        DisplayName=ctx.unique_name("sim2real-behav-audit-user-"),
        Name={"GivenName": "Audit", "FamilyName": "Fields"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    before = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert before.get("CreatedBy"), f"expected CreatedBy populated on a fresh user, got {before.get('CreatedBy')!r}"
    assert before.get("UpdatedBy"), f"expected UpdatedBy populated on a fresh user, got {before.get('UpdatedBy')!r}"
    created_at = before["CreatedAt"]

    idstore.update_user(
        IdentityStoreId=store_id,
        UserId=user_id,
        Operations=[{"AttributePath": "title", "AttributeValue": "audit-field-check"}],
    )

    # Timestamp resolution may not distinguish CreatedAt from an immediately-following UpdatedAt;
    # retry the independent read (bounded) rather than assume a fixed sleep clears it.
    deadline = time.monotonic() + 30
    after = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    while after["UpdatedAt"] <= created_at and time.monotonic() < deadline:
        time.sleep(1)
        after = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)

    assert after.get("CreatedBy"), f"expected CreatedBy populated after update, got {after.get('CreatedBy')!r}"
    assert after.get("UpdatedBy"), f"expected UpdatedBy populated after update, got {after.get('UpdatedBy')!r}"
    assert after["CreatedAt"] == created_at, (
        f"expected CreatedAt to stay {created_at} across an update, got {after['CreatedAt']}"
    )
    assert after["UpdatedAt"] > created_at, (
        f"expected UpdatedAt to advance past CreatedAt={created_at} within 30s, got UpdatedAt={after['UpdatedAt']}"
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


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
