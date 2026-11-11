"""update-user-attributes-persist."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-user-attributes-persist"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateUser's replace Operations mutate exactly the targeted attribute paths, and the
    mutation is durably visible on a subsequent DescribeUser."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-user-"),
        DisplayName=ctx.unique_name("sim2real-user-"),
        NickName="Old",
        Name={"GivenName": "Original", "FamilyName": "Doe"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    before = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert before["NickName"] == "Old", f"expected pre-update NickName 'Old', got {before['NickName']!r}"
    assert before["Name"]["FamilyName"] == "Doe", (
        f"expected pre-update FamilyName 'Doe', got {before['Name']['FamilyName']!r}"
    )

    idstore.update_user(
        IdentityStoreId=store_id,
        UserId=user_id,
        Operations=[
            {"AttributePath": "nickName", "AttributeValue": "Johnny"},
            {"AttributePath": "name.familyName", "AttributeValue": "Smith"},
        ],
    )

    after = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert after["NickName"] == "Johnny", f"expected NickName 'Johnny' after replace, got {after['NickName']!r}"
    assert after["Name"]["FamilyName"] == "Smith", (
        f"expected FamilyName 'Smith' after replace, got {after['Name']['FamilyName']!r}"
    )
    # untouched attribute must remain unchanged
    assert after["Name"]["GivenName"] == "Original", (
        f"untargeted GivenName must remain 'Original', got {after['Name']['GivenName']!r}"
    )
    assert after["UpdatedAt"] > before["UpdatedAt"], (
        f"UpdatedAt must advance past its pre-update value {before['UpdatedAt']!r} after "
        f"UpdateUser, got {after['UpdatedAt']!r}"
    )


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _get_identity_store_id(ctx):
    ssoadmin = ctx.client("sso-admin")
    try:
        resp = ssoadmin.list_instances()
    except Exception as exc:
        raise AssertionError(
            f"ssoadmin.list_instances is unavailable ({exc}); identitystore has no API of its "
            "own to provision an identity store, so a pre-existing (or emulator-seeded) IAM "
            "Identity Center instance is required"
        ) from exc
    instances = resp.get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        created = ssoadmin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except Exception as exc:
        raise AssertionError(
            f"no IAM Identity Center instance exists and ssoadmin.create_instance failed ({exc}); "
            "this is expected for AWS Organizations management/member accounts, which reject "
            "self-service instance creation -- run against a standalone account or an emulator "
            "that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
    deadline = _time.monotonic() + 180
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(3)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 180s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
