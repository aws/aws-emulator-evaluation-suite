"""user-without-optional-fields-omitted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "user-without-optional-fields-omitted"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A user created without Title/NickName (both optional) has those keys entirely absent
    from DescribeUser, rather than defaulted to an empty string. DisplayName/Name are the only
    required identity attributes besides UserName."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    bare_name = ctx.unique_name("sim2real-behav-nooptional-user-")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=bare_name,
        DisplayName=bare_name,
        Name={"GivenName": "No", "FamilyName": "Optional"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    described = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert "Title" not in described, f"expected Title absent, got key present: {described.get('Title')!r}"
    assert "NickName" not in described, (
        f"expected NickName absent, got key present: {described.get('NickName')!r}"
    )

    # Positive control: a user created WITH those optional fields does surface them.
    other_name = ctx.unique_name("sim2real-behav-withoptional-user-")
    other_user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=other_name,
        DisplayName=other_name,
        Name={"GivenName": "Has", "FamilyName": "Optional"},
        Title="Has A Title",
        NickName="Has A NickName",
    )["UserId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=other_user_id))
    )
    other_described = idstore.describe_user(IdentityStoreId=store_id, UserId=other_user_id)
    assert other_described["Title"] == "Has A Title", (
        f"expected Title='Has A Title', got {other_described.get('Title')!r}"
    )
    assert other_described["NickName"] == "Has A NickName", (
        f"expected NickName='Has A NickName', got {other_described.get('NickName')!r}"
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
