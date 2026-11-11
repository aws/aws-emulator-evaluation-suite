"""username-with-space-rejected."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "username-with-space-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateUser rejects a UserName containing a literal space (UserName's pattern excludes
    whitespace, unlike DisplayName) with ValidationException, and no user is created. The same
    base name without the space is a positive control that succeeds, then is proven deleted."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    base = ctx.unique_name("sim2real-user-")
    invalid_username = base + " invalid"

    code, message = _error(lambda: idstore.create_user(IdentityStoreId=store_id, UserName=invalid_username))
    assert code == "ValidationException", (
        f"expected CreateUser to reject UserName {invalid_username!r} with ValidationException, got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'userName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no user was created for the malformed name
    not_found_code, not_found_message = _error(
        lambda: idstore.get_user_id(
            IdentityStoreId=store_id,
            AlternateIdentifier={
                "UniqueAttribute": {"AttributePath": "userName", "AttributeValue": invalid_username}
            },
        )
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected no user to exist for the rejected UserName {invalid_username!r}, "
        f"but get_user_id returned code {not_found_code!r}"
    )
    assert not_found_message == "USER not found.", (
        f"expected get_user_id to say 'USER not found.', got {not_found_message!r}"
    )

    # positive control: the same base name without the space is a valid UserName
    valid_user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=base,
        DisplayName=base,
        Name={"GivenName": "Valid", "FamilyName": "Username"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=valid_user_id)))
    described = idstore.describe_user(IdentityStoreId=store_id, UserId=valid_user_id)
    assert described["UserName"] == base, (
        f"expected the positive-control UserName to be {base!r}, got {described.get('UserName')!r}"
    )

    # the positive control is then deleted and proven gone via an independent read -- the delete
    # is already mandatory cleanup, so this makes it a real negative assertion instead of a no-op
    idstore.delete_user(IdentityStoreId=store_id, UserId=valid_user_id)
    gone_code, gone_message = _error(lambda: idstore.describe_user(IdentityStoreId=store_id, UserId=valid_user_id))
    assert gone_code == "ResourceNotFoundException", (
        f"expected the deleted positive-control user {valid_user_id!r} to be gone, got {gone_code!r}"
    )
    assert gone_message == "User not found", (
        f"expected DescribeUser on the deleted user to say 'User not found', got {gone_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because a target
    accepting input real AWS refuses is the strongest signal available and must not be reported
    as a code mismatch (or, for a not-found probe, as a silently-wrong absence claim)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _ready_identity_store_id(instances):
    for inst in instances:
        if inst.get("IdentityStoreId"):
            return inst["IdentityStoreId"]
    return None


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
    found = _ready_identity_store_id(instances)
    if found:
        return found
    if not instances:
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
    # An instance can exist (pre-existing or just created) with its IdentityStoreId not yet
    # populated -- list_instances is polled until a ready id appears, not subscripted once.
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        found = _ready_identity_store_id(resp.get("Instances", []))
        if found:
            return found
        _time.sleep(1)
    raise AssertionError(
        "an IAM Identity Center instance exists but its IdentityStoreId never appeared via "
        "list_instances within 30s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
