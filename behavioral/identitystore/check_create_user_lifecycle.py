"""create-user-lifecycle."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-user-lifecycle"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateUser -> DescribeUser reflects attributes and ENABLED status; DeleteUser -> exists->deleted."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-user-")

    resp = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=username,
        DisplayName="Sim2Real Test User",
        Name={"GivenName": "Sim", "FamilyName": "User"},
    )
    user_id = resp["UserId"]
    ctx.on_cleanup(_teardown(
        lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id),
        "ResourceNotFoundException",
    ))

    described = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert described["UserName"] == username, f"expected UserName {username!r}, got {described.get('UserName')!r}"
    assert described["DisplayName"] == "Sim2Real Test User", (
        f"expected DisplayName 'Sim2Real Test User', got {described.get('DisplayName')!r}"
    )
    assert described["Name"]["GivenName"] == "Sim", f"expected GivenName 'Sim', got {described['Name'].get('GivenName')!r}"
    assert described["Name"]["FamilyName"] == "User", (
        f"expected FamilyName 'User', got {described['Name'].get('FamilyName')!r}"
    )
    assert described["UserStatus"] == "ENABLED", f"expected UserStatus ENABLED, got {described.get('UserStatus')!r}"
    assert "CreatedAt" in described, f"expected DescribeUser to report CreatedAt, got keys {sorted(described)}"

    idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)
    err = _error(lambda: idstore.describe_user(IdentityStoreId=store_id, UserId=user_id))
    assert err == ("ResourceNotFoundException", "User not found"), (
        f"expected DescribeUser on a deleted user to 404 'User not found', got {err!r}"
    )

    # The user is not just invisible -- it is unusable: a mutation on the dead id fails too.
    mutate_err = _error(
        lambda: idstore.update_user(
            IdentityStoreId=store_id,
            UserId=user_id,
            Operations=[{"AttributePath": "displayName", "AttributeValue": "should not apply"}],
        )
    )
    assert mutate_err == ("ResourceNotFoundException", "User not found"), (
        f"expected UpdateUser on an already-deleted user to 404 'User not found', got {mutate_err!r}"
    )


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, unless already gone."""

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
            if inst.get("InstanceArn") == instance_arn:
                store_id = inst.get("IdentityStoreId")
                if store_id:
                    return store_id
                break  # ARN is visible but IdentityStoreId has not propagated yet; keep polling.
        _time.sleep(1)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 60s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
