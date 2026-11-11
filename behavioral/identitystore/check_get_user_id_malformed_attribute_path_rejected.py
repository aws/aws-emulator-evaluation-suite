"""get-user-id-malformed-attribute-path-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-user-id-malformed-attribute-path-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """GetUserId rejects a UniqueAttribute AttributePath containing digits: the AttributePath
    pattern only allows letters (optionally dotted/colon-scoped), never digits or punctuation."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    username = ctx.unique_name("sim2real-behav-user-")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Malformed", "FamilyName": "AttrPath"},
    )["UserId"]

    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    error = _client_error(
        lambda: idstore.get_user_id(
            IdentityStoreId=store_id,
            AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName123", "AttributeValue": username}},
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"GetUserId with a digit-bearing AttributePath was rejected with {error.get('Code')!r}, "
        f"expected 'ValidationException'"
    )
    assert error.get("Message") == (
        "1 validation error detected: Value 'userName123' at "
        "'alternateIdentifier.uniqueAttribute.attributePath' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        r"(?:\p{L}+:\p{L}+:\p{L}+(?:\.\p{L}+){0,3}|\p{L}+(?:\.\p{L}+){0,2})"
    ), f"expected AWS's exact ValidationException message, got {error.get('Message')!r}"

    # Positive control: the same lookup with a well-formed AttributePath ("userName") resolves.
    resolved = idstore.get_user_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": username}},
    )
    assert resolved["UserId"] == user_id, (
        f"GetUserId with a well-formed AttributePath returned {resolved['UserId']!r}, "
        f"expected the created user {user_id!r}"
    )

    idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)
    gone = _client_error(lambda: idstore.describe_user(IdentityStoreId=store_id, UserId=user_id))
    assert gone.get("Code") == "ResourceNotFoundException", (
        f"DescribeUser on a deleted user returned {gone.get('Code')!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    assert gone.get("Message") == "User not found", (
        f"DescribeUser on a deleted user said {gone.get('Message')!r}, expected 'User not found'"
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


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
