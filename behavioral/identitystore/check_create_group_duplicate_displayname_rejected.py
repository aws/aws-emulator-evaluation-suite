"""create-group-duplicate-displayname-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-group-duplicate-displayname-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A second CreateGroup with a DisplayName already in use is rejected; the original is untouched."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-behav-dup-group-")
    original_id = idstore.create_group(IdentityStoreId=store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=original_id)))

    err = _error(
        lambda: idstore.create_group(IdentityStoreId=store_id, DisplayName=display_name),
        on_unexpected_success=lambda resp: ctx.on_cleanup(
            lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=resp["GroupId"]))
        ),
    )
    assert err == ("ConflictException", "Duplicate GroupDisplayName"), (
        f"expected ConflictException 'Duplicate GroupDisplayName' for a colliding DisplayName, got {err!r}"
    )

    # Effect absent: the lookup still resolves to the ORIGINAL group, no second one was created.
    resolved = idstore.get_group_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": display_name}},
    )
    assert resolved["GroupId"] == original_id, (
        f"expected the DisplayName to still resolve to the original group {original_id!r}, "
        f"got {resolved['GroupId']!r}"
    )

    # Positive control: a group with a genuinely different DisplayName still succeeds.
    control_name = ctx.unique_name("sim2real-behav-dup-group-control-")
    control_id = idstore.create_group(IdentityStoreId=store_id, DisplayName=control_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=control_id)))
    control_described = idstore.describe_group(IdentityStoreId=store_id, GroupId=control_id)["DisplayName"]
    assert control_described == control_name, (
        f"expected control group {control_id!r} to describe DisplayName {control_name!r}, "
        f"got {control_described!r}"
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


def _error(fn, *, on_unexpected_success=None):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    if on_unexpected_success is not None:
        on_unexpected_success(result)
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
