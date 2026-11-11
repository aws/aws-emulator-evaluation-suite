"""list-users-pagination-next-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-users-pagination-next-token"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListUsers honors MaxResults and NextToken advances to a disjoint page of results."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    user_ids = []
    for i in range(2):
        uid = idstore.create_user(
            IdentityStoreId=store_id,
            UserName=ctx.unique_name(f"sim2real-behav-page{i}-"),
            DisplayName=ctx.unique_name(f"sim2real-behav-page{i}-"),
            Name={"GivenName": "Page", "FamilyName": str(i)},
        )["UserId"]
        ctx.on_cleanup(lambda uid=uid: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=uid)))
        user_ids.append(uid)

    # With at least our 2 users present, a single-item page must not exhaust the store.
    page1 = idstore.list_users(IdentityStoreId=store_id, MaxResults=1)
    assert len(page1["Users"]) == 1, f"MaxResults=1 must cap the page at 1, got {len(page1['Users'])}"
    assert page1.get("NextToken"), "at least 2 users exist, so a 1-item page must carry a NextToken"

    page2 = idstore.list_users(IdentityStoreId=store_id, MaxResults=5, NextToken=page1["NextToken"])
    assert len(page2["Users"]) >= 1, f"page2 must not be empty when a NextToken was returned, got {len(page2['Users'])}"

    page1_ids = {u["UserId"] for u in page1["Users"]}
    page2_ids = {u["UserId"] for u in page2["Users"]}
    assert page1_ids.isdisjoint(page2_ids), (
        f"NextToken must advance to a disjoint page, but page1={page1_ids} and page2={page2_ids} overlap"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
