"""duplicate-group-display-name-conflict-rejected."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "duplicate-group-display-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateGroup with a DisplayName that collides with an existing group is rejected with
    ConflictException, the original group is left as the sole owner of that name, and a
    control group with a distinct name still creates successfully in the same store."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    display_name = ctx.unique_name("sim2real-dupgroup-")
    original_group_id = idstore.create_group(IdentityStoreId=store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(
        _teardown(
            lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=original_group_id),
            "ResourceNotFoundException",
        )
    )

    code, message = _client_error(
        lambda: idstore.create_group(IdentityStoreId=store_id, DisplayName=display_name)
    )
    assert code == "ConflictException", f"expected ConflictException on duplicate DisplayName, got {code!r}"
    assert message == "Duplicate GroupDisplayName", (
        f"expected AWS's exact ConflictException message, got {message!r}"
    )

    # effect absent: the name still resolves to exactly the original group
    resolved = idstore.get_group_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={
            "UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": display_name}
        },
    )
    assert resolved["GroupId"] == original_group_id, (
        f"expected displayName lookup to still resolve to the original group {original_group_id!r}, "
        f"got {resolved['GroupId']!r}"
    )

    # positive control: a group with a distinct name still creates fine -- proven by an
    # independent read at the destination, not by comparing the two generated ids (which
    # can never collide and so can never fail).
    control_display_name = ctx.unique_name("sim2real-control-group-")
    control_group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=control_display_name
    )["GroupId"]
    ctx.on_cleanup(
        _teardown(
            lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=control_group_id),
            "ResourceNotFoundException",
        )
    )
    resolved_control = idstore.get_group_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={
            "UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": control_display_name}
        },
    )
    assert resolved_control["GroupId"] == control_group_id, (
        f"expected the control group's displayName to resolve to {control_group_id!r}, "
        f"got {resolved_control['GroupId']!r}"
    )


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _teardown(undo, *not_found: str):
    """Run ``undo()``; raise unless it fails with one of ``undo``'s own not_found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


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
    ctx.on_cleanup(_teardown(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
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
