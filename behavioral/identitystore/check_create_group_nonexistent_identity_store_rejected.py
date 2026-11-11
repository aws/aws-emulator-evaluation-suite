"""create-group-nonexistent-identity-store-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-group-nonexistent-identity-store-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateGroup into a well-formed but nonexistent IdentityStoreId is rejected and creates nothing."""
    real_store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    # Well-formed per the `d-[0-9a-f]{10}` pattern, but not the real store and not created by anyone.
    bogus_store_id = "d-9999999999"
    assert bogus_store_id != real_store_id, (
        f"test setup bug: the bogus store id {bogus_store_id!r} collides with the real "
        f"IdentityStoreId {real_store_id!r}, so the negative would not exercise a nonexistent store"
    )

    display_name = ctx.unique_name("sim2real-behav-scope-group-")
    err = _error(
        lambda: idstore.create_group(IdentityStoreId=bogus_store_id, DisplayName=display_name)
    )
    expected = ("ResourceNotFoundException", f"IdentityStore not present for IdentityStoreId: {bogus_store_id}")
    assert err == expected, (
        f"expected {expected!r} for CreateGroup against nonexistent "
        f"IdentityStoreId {bogus_store_id!r}, got {err!r}"
    )

    # Effect absent: no group with this DisplayName exists in the REAL store either.
    lookup_err = _error(
        lambda: idstore.get_group_id(
            IdentityStoreId=real_store_id,
            AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": display_name}},
        )
    )
    assert lookup_err == ("ResourceNotFoundException", "GROUP not found."), (
        f"expected no group named {display_name!r} to exist anywhere in the real store "
        f"{real_store_id!r} after the rejected CreateGroup, got GetGroupId error {lookup_err!r}"
    )

    # Positive control: the identical request against the REAL store succeeds.
    group_id = idstore.create_group(IdentityStoreId=real_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=real_store_id, GroupId=group_id)))
    described_name = idstore.describe_group(IdentityStoreId=real_store_id, GroupId=group_id)["DisplayName"]
    assert described_name == display_name, (
        f"positive control: expected DescribeGroup on the real store to reflect DisplayName "
        f"{display_name!r}, got {described_name!r}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
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
    raise AssertionError(
        "no IAM Identity Center instance could be enabled in this account/region"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
