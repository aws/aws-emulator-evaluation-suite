"""invalid-identity-store-id-pattern-validation-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invalid-identity-store-id-pattern-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateUser rejects an IdentityStoreId that fails the documented `d-[0-9a-f]{10}` pattern,
    before any user is created, and the identical call against the real store succeeds."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    username = ctx.unique_name("sim2real-behav-pattern-user-")
    malformed_store_id = "not-a-valid-identity-store-id"

    code, message = _client_error(
        lambda: idstore.create_user(
            IdentityStoreId=malformed_store_id,
            UserName=username,
            DisplayName=username,
            Name={"GivenName": "Pattern", "FamilyName": "Reject"},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed IdentityStoreId, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{malformed_store_id}' at 'identityStoreId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        r"(arn:aws(-[a-z]{1,5}){0,3}:identitystore::\d{12}:identitystore/)?(d-[0-9a-f]{10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    ), (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # Effect absent: no user with this UserName exists in the REAL store either.
    lookup_code, lookup_message = _client_error(
        lambda: idstore.get_user_id(
            IdentityStoreId=store_id,
            AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": username}},
        )
    )
    assert lookup_code == "ResourceNotFoundException", (
        f"expected the rejected call to have created nothing, got {lookup_code!r}"
    )
    assert lookup_message == "USER not found.", (
        f"expected AWS's exact ResourceNotFoundException message, got {lookup_message!r}"
    )

    # Positive control: the identical call against the REAL store succeeds.
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Pattern", "FamilyName": "Reject"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    described = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert described["UserName"] == username, (
        f"expected UserName {username!r} on the real store, got {described.get('UserName')!r}"
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


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
