"""get-group-id-by-display-name."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-group-id-by-display-name"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """GetGroupId resolves the exact GroupId for a UniqueAttribute lookup on displayName,
    distinguishes it from a same-store decoy with a different displayName, and rejects a
    displayName that was never created."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    display_name = ctx.unique_name("sim2real-group-")
    group_id = idstore.create_group(IdentityStoreId=store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(_teardown(
        lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id), "ResourceNotFoundException",
    ))

    # decoy in the same store: a target that ignores AttributeValue and returns "the" group (e.g.
    # the only or the most-recently-created one) must still fail one of the two lookups below.
    decoy_name = ctx.unique_name("sim2real-group-decoy-")
    decoy_id = idstore.create_group(IdentityStoreId=store_id, DisplayName=decoy_name)["GroupId"]
    ctx.on_cleanup(_teardown(
        lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=decoy_id), "ResourceNotFoundException",
    ))

    resp = idstore.get_group_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={
            "UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": display_name}
        },
    )
    assert resp["GroupId"] == group_id, f"expected GetGroupId to resolve {group_id!r}, got {resp['GroupId']!r}"
    assert resp["IdentityStoreId"] == store_id, (
        f"expected GetGroupId to echo IdentityStoreId {store_id!r}, got {resp['IdentityStoreId']!r}"
    )

    decoy_resp = idstore.get_group_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={
            "UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": decoy_name}
        },
    )
    assert decoy_resp["GroupId"] == decoy_id, (
        f"expected GetGroupId to resolve the decoy {decoy_id!r} for its own displayName, got "
        f"{decoy_resp['GroupId']!r}"
    )

    bogus_name = ctx.unique_name("sim2real-group-absent-")
    code, message = _client_error(
        lambda: idstore.get_group_id(
            IdentityStoreId=store_id,
            AlternateIdentifier={
                "UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": bogus_name}
            },
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a displayName that was never created, got {code!r}"
    )
    assert message == "GROUP not found.", (
        f"expected AWS's exact ResourceNotFoundException message, got {message!r}"
    )


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _teardown(undo, *not_found: str):
    """``undo()`` where a failed delete raises; only ``not_found`` codes mean it is already gone."""

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
    instance_arn = None
    if not instances:
        try:
            created = ssoadmin.create_instance(
                Name=ctx.unique_name("sim2real-idc-"),
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except Exception as exc:
            raise AssertionError(
                f"no IAM Identity Center instance exists and ssoadmin.create_instance failed ({exc}); "
                "this is expected for AWS Organizations management/member accounts, which reject "
                "self-service instance creation -- run against a standalone account or an emulator "
                "that seeds a default identity store"
            ) from exc
        instance_arn = created["InstanceArn"]
        ctx.on_cleanup(_teardown(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
        instances = []

    def _ready_id(candidates):
        for inst in candidates:
            if instance_arn is not None and inst.get("InstanceArn") != instance_arn:
                continue
            if "IdentityStoreId" in inst:
                return inst["IdentityStoreId"]
        return None

    ready = _ready_id(instances)
    if ready is not None:
        return ready

    # Either an adopted instance or one this check just created has not finished provisioning
    # yet -- IdentityStoreId is assigned after the instance first appears via ListInstances, not
    # atomically with it, so a hard subscript on the first list_instances() response is a race.
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        ready = _ready_id(resp.get("Instances", []))
        if ready is not None:
            return ready
        _time.sleep(1)
    raise AssertionError(
        "an IAM Identity Center instance exists but its IdentityStoreId never appeared via "
        "list_instances within 30s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
