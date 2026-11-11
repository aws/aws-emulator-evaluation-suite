"""update-user-phone-numbers-full-replace."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-user-phone-numbers-full-replace"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateUser on phoneNumbers replaces the whole element rather than merging into it: the new
    element (no Type/Primary) has value 832-555-0100 and the old element's Type 'work' and
    Primary false do not survive."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-user-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-"),
        Name={"GivenName": "Phone", "FamilyName": "Owner"},
        PhoneNumbers=[{"Value": "555-010-0001", "Type": "work", "Primary": False}],
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    before = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert len(before["PhoneNumbers"]) == 1, f"expected the seeded phone number, got {before['PhoneNumbers']!r}"
    assert before["PhoneNumbers"][0]["Type"] == "work", f"seed did not persist Type: {before['PhoneNumbers'][0]!r}"
    assert before["PhoneNumbers"][0]["Primary"] is False, f"seed did not persist Primary: {before['PhoneNumbers'][0]!r}"

    idstore.update_user(
        IdentityStoreId=store_id,
        UserId=user_id,
        Operations=[
            {
                "AttributePath": "phoneNumbers",
                "AttributeValue": [{"Value": "832-555-0100"}],
            }
        ],
    )

    described = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    phones = described["PhoneNumbers"]
    assert len(phones) == 1, f"expected exactly one phone number after update, got {phones!r}"
    assert phones[0]["Value"] == "832-555-0100", f"expected the new number, got {phones[0]!r}"
    assert phones[0].get("Type") != "work", (
        f"the old element's Type='work' survived an update that supplied no Type -- "
        f"the target merged fields into the existing element instead of replacing it wholesale: {phones[0]!r}"
    )
    assert phones[0].get("Primary") is not False, (
        f"the old element's Primary=False survived an update that supplied no Primary -- "
        f"the target merged fields into the existing element instead of replacing it wholesale: {phones[0]!r}"
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
