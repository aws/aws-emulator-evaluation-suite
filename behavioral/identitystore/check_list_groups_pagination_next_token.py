"""list-groups-pagination-next-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-groups-pagination-next-token"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListGroups honors MaxResults and NextToken advances to a disjoint page of results."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    group_ids = []
    for i in range(2):
        gid = idstore.create_group(
            IdentityStoreId=store_id, DisplayName=ctx.unique_name(f"sim2real-behav-gpage{i}-")
        )["GroupId"]
        ctx.on_cleanup(lambda gid=gid: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=gid)))
        group_ids.append(gid)

    # With at least our 2 groups present, a single-item page must not exhaust the store.
    page1 = idstore.list_groups(IdentityStoreId=store_id, MaxResults=1)
    assert len(page1["Groups"]) == 1
    assert page1.get("NextToken")

    page2 = idstore.list_groups(IdentityStoreId=store_id, MaxResults=5, NextToken=page1["NextToken"])
    assert len(page2["Groups"]) >= 1

    page1_ids = {g["GroupId"] for g in page1["Groups"]}
    page2_ids = {g["GroupId"] for g in page2["Groups"]}
    assert page1_ids.isdisjoint(page2_ids)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
