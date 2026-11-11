"""create-group-lifecycle."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-group-lifecycle"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateGroup -> DescribeGroup reflects attributes; DeleteGroup -> exists->deleted."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-group-")

    resp = idstore.create_group(
        IdentityStoreId=store_id,
        DisplayName=display_name,
        Description="Sim2Real behavioral test group",
    )
    group_id = resp["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert described["DisplayName"] == display_name, (
        f"DescribeGroup DisplayName mismatch: expected {display_name!r}, got {described.get('DisplayName')!r}"
    )
    assert described["Description"] == "Sim2Real behavioral test group", (
        f"DescribeGroup Description mismatch: expected 'Sim2Real behavioral test group', "
        f"got {described.get('Description')!r}"
    )
    assert described["IdentityStoreId"] == store_id, (
        f"DescribeGroup IdentityStoreId mismatch: expected {store_id!r}, got {described.get('IdentityStoreId')!r}"
    )
    assert "CreatedAt" in described, "DescribeGroup response is missing CreatedAt"

    idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)
    err = _error(lambda: idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id))
    assert err == ("ResourceNotFoundException", "Group not found"), (
        f"expected DescribeGroup after DeleteGroup to fail ResourceNotFoundException 'Group not found', got {err!r}"
    )


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises instead of
    returning a sentinel, so an over-permissive target cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe(fn):
    """Cleanup helper: swallow only a target that is already gone; a genuine failed delete raises."""
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
    deadline = _time.monotonic() + 60
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(1)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 60s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
