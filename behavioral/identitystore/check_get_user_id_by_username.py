"""get-user-id-by-username."""
from __future__ import annotations

import time as _time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-user-id-by-username"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """GetUserId resolves the exact UserId for a UniqueAttribute lookup on userName, distinguishes
    it from a same-store decoy with a different userName, and rejects a userName that was never
    created."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    username = ctx.unique_name("sim2real-user-")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Get", "FamilyName": "ByUsername"},
    )["UserId"]
    ctx.on_cleanup(_teardown(
        lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id), "ResourceNotFoundException",
    ))

    # decoy in the same store: a target that ignores AttributeValue and returns "the" user (e.g.
    # the only or the most-recently-created one) must still fail one of the two lookups below.
    decoy_username = ctx.unique_name("sim2real-user-decoy-")
    decoy_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=decoy_username,
        DisplayName=decoy_username,
        Name={"GivenName": "Decoy", "FamilyName": "ByUsername"},
    )["UserId"]
    ctx.on_cleanup(_teardown(
        lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=decoy_id), "ResourceNotFoundException",
    ))

    resp = idstore.get_user_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": username}},
    )
    assert resp["UserId"] == user_id, f"expected UserId {user_id} for userName {username!r}, got {resp['UserId']!r}"
    assert resp["IdentityStoreId"] == store_id, (
        f"expected IdentityStoreId {store_id}, got {resp['IdentityStoreId']!r}"
    )

    decoy_resp = idstore.get_user_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": decoy_username}},
    )
    assert decoy_resp["UserId"] == decoy_id, (
        f"expected UserId {decoy_id} for decoy userName {decoy_username!r}, got {decoy_resp['UserId']!r}"
    )

    bogus_username = f"sim2real-user-absent-{uuid.uuid4()}"
    code, message = _client_error(
        lambda: idstore.get_user_id(
            IdentityStoreId=store_id,
            AlternateIdentifier={
                "UniqueAttribute": {"AttributePath": "userName", "AttributeValue": bogus_username}
            },
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a userName that was never created, got {code!r}"
    )
    assert message == "USER not found.", (
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
    deadline = _time.monotonic() + 60
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(2)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 60s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
