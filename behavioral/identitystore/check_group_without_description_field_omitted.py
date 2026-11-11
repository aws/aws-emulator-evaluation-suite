"""group-without-description-field-omitted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "group-without-description-field-omitted"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A group created without a Description has the key entirely absent from DescribeGroup and
    ListGroups responses, rather than defaulted to an empty string."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    display_name = ctx.unique_name("sim2real-behav-nodesc-group-")
    group_id = idstore.create_group(IdentityStoreId=store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert "Description" not in described, f"expected Description key absent, got {described!r}"

    listed = idstore.list_groups(IdentityStoreId=store_id, MaxResults=100)
    matching = [g for g in listed["Groups"] if g["GroupId"] == group_id]
    assert len(matching) == 1, f"expected exactly 1 matching group, got {len(matching)}"
    assert "Description" not in matching[0], f"expected Description key absent from ListGroups entry, got {matching[0]!r}"

    # Positive control: a group created WITH a description does surface the key.
    other_group_id = idstore.create_group(
        IdentityStoreId=store_id,
        DisplayName=ctx.unique_name("sim2real-behav-withdesc-group-"),
        Description="present",
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=other_group_id))
    )
    other_described = idstore.describe_group(IdentityStoreId=store_id, GroupId=other_group_id)
    assert other_described["Description"] == "present", (
        f"expected Description=='present', got {other_described.get('Description')!r}"
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


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
