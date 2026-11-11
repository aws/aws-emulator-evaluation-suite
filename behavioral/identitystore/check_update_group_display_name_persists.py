"""update-group-display-name-persists."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-group-display-name-persists"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateGroup's replace Operation on displayName/description mutates the group and the
    change is durably visible on a subsequent DescribeGroup."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    original_name = ctx.unique_name("sim2real-group-")
    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=original_name, Description="before"
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    new_name = original_name + "-renamed"
    idstore.update_group(
        IdentityStoreId=store_id,
        GroupId=group_id,
        Operations=[
            {"AttributePath": "displayName", "AttributeValue": new_name},
            {"AttributePath": "description", "AttributeValue": "after"},
        ],
    )

    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert described["DisplayName"] == new_name, (
        f"expected DisplayName {new_name!r} after UpdateGroup, got {described['DisplayName']!r}"
    )
    assert described["Description"] == "after", (
        f"expected Description 'after' after UpdateGroup, got {described['Description']!r}"
    )
    assert described["DisplayName"] != original_name, (
        f"DisplayName {described['DisplayName']!r} should not equal the pre-update name {original_name!r}"
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
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(1)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 30s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
