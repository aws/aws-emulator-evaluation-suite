"""create-group-describe-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-group-describe-fields"
GROUP = "lifecycle"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DescribeGroup echoes the DisplayName/Description submitted at CreateGroup time, and an
    independent read confirms DeleteGroup actually removed it."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-behav-group-")
    resp = idstore.create_group(
        IdentityStoreId=store_id,
        DisplayName=display_name,
        Description="behavioral fidelity check group",
    )
    group_id = resp["GroupId"]
    assert resp["IdentityStoreId"] == store_id, (
        f"CreateGroup echoed IdentityStoreId {resp['IdentityStoreId']!r}, expected {store_id!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert described["GroupId"] == group_id, (
        f"DescribeGroup returned GroupId {described['GroupId']!r}, expected {group_id!r}"
    )
    assert described["DisplayName"] == display_name, (
        f"DescribeGroup returned DisplayName {described['DisplayName']!r}, expected {display_name!r}"
    )
    assert described["Description"] == "behavioral fidelity check group", (
        f"DescribeGroup returned Description {described['Description']!r}, "
        "expected the value submitted at CreateGroup"
    )
    assert described["IdentityStoreId"] == store_id, (
        f"DescribeGroup returned IdentityStoreId {described['IdentityStoreId']!r}, expected {store_id!r}"
    )
    assert "CreatedAt" in described, "DescribeGroup response is missing CreatedAt"

    idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)
    err = _error(lambda: idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id))
    assert err == ("ResourceNotFoundException", "Group not found"), (
        f"DescribeGroup after DeleteGroup returned {err!r}, expected ResourceNotFoundException 'Group not found'"
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


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
