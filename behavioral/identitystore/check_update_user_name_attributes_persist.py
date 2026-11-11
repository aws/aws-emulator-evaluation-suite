"""update-user-name-attributes-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-user-name-attributes-persist"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateUser with dotted AttributePaths (name.familyName / name.givenName) mutates the nested Name struct."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-behav-user-")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-user-"),
        DisplayName=display_name,
        Name={"GivenName": "Original", "FamilyName": "Name"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    idstore.update_user(
        IdentityStoreId=store_id,
        UserId=user_id,
        Operations=[
            {"AttributePath": "name.familyName", "AttributeValue": "Smith"},
            {"AttributePath": "name.givenName", "AttributeValue": "Jane"},
        ],
    )

    described = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert described["Name"]["FamilyName"] == "Smith", f"expected FamilyName=Smith, got {described['Name'].get('FamilyName')!r}"
    assert described["Name"]["GivenName"] == "Jane", f"expected GivenName=Jane, got {described['Name'].get('GivenName')!r}"
    # An unrelated attribute must be untouched by the two nested-path operations.
    assert described["DisplayName"] == display_name, (
        f"expected DisplayName to be untouched ({display_name!r}), got {described['DisplayName']!r}"
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
