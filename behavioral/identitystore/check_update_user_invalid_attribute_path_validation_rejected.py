"""update-user-invalid-attribute-path-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-invalid-attribute-path-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateUser rejects an AttributePath that fails the attribute-path pattern, and leaves the user untouched."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-idstore-user-")
    user_id = idc.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        DisplayName="Original Display Name",
        Name={"GivenName": "Sim", "FamilyName": "Parity"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, identity_store_id, user_id))

    # AttributePath must start with a letter category; "1bad" violates the pattern.
    code, message = _error(
        lambda: idc.update_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id,
            Operations=[{"AttributePath": "1bad", "AttributeValue": "x"}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException for malformed AttributePath, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '1bad' at 'operations.1.member.attributePath' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "(?:\\p{L}+:\\p{L}+:\\p{L}+(?:\\.\\p{L}+){0,3}|\\p{L}+(?:\\.\\p{L}+){0,2})"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected update did not change the user's attributes.
    unchanged = idc.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    assert unchanged["DisplayName"] == "Original Display Name", (
        f"expected DisplayName unchanged at 'Original Display Name', got {unchanged['DisplayName']!r}"
    )

    # Positive control: UpdateUser with a well-formed AttributePath still succeeds and persists.
    idc.update_user(
        IdentityStoreId=identity_store_id,
        UserId=user_id,
        Operations=[{"AttributePath": "displayName", "AttributeValue": "Changed Display Name"}],
    )
    changed = idc.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    assert changed["DisplayName"] == "Changed Display Name", (
        f"expected DisplayName updated to 'Changed Display Name', got {changed['DisplayName']!r}"
    )


def _get_identity_store_id(ctx) -> str:
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


def _safe_delete_user(ctx, identity_store_id: str, user_id: str) -> None:
    idc = ctx.client("identitystore")
    try:
        idc.delete_user(IdentityStoreId=identity_store_id, UserId=user_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn() and return the (code, message) of its ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
