"""delete-user-removes-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-user-removes-resource"
GROUP = "lifecycle"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DeleteUser removes the user: a subsequent DescribeUser reports ResourceNotFoundException,
    and a mutation against the now-dead id (UpdateUser) is rejected the same way rather than
    succeeding against a resource an independent read just said is gone."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-behav-user-")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Grace", "FamilyName": "Hopper"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete_user(idstore, store_id, user_id))

    # Positive control: the user is describable before deletion.
    described = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert described["UserId"] == user_id, (
        f"expected DescribeUser to echo UserId {user_id!r} before deletion, got {described.get('UserId')!r}"
    )

    idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)

    code, message = _client_error(lambda: idstore.describe_user(IdentityStoreId=store_id, UserId=user_id))
    assert code == "ResourceNotFoundException", (
        f"expected DescribeUser on a deleted UserId to raise ResourceNotFoundException, got {code!r}"
    )
    assert message == "User not found", (
        f"expected DescribeUser on a deleted UserId to say 'User not found', got {message!r}"
    )

    # A mutation against the now-dead id must fail the same way, not succeed against a resource
    # that the independent read above already proved is gone.
    update_code, update_message = _client_error(
        lambda: idstore.update_user(
            IdentityStoreId=store_id,
            UserId=user_id,
            Operations=[{"AttributePath": "displayName", "AttributeValue": "post-delete-mutation"}],
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateUser on a deleted UserId to raise ResourceNotFoundException, got {update_code!r}"
    )
    assert update_message == "User not found", (
        f"expected UpdateUser on a deleted UserId to say 'User not found', got {update_message!r}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
    import time
    from botocore.exceptions import ClientError

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
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_user(idstore, store_id, user_id) -> None:
    try:
        idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
