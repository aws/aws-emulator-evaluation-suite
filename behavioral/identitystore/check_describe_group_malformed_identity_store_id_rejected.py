"""describe-group-malformed-identity-store-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-group-malformed-identity-store-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DescribeGroup rejects an IdentityStoreId that fails the documented pattern constraint."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-behav-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    malformed_store_id = "not-a-valid-identity-store-id"
    code, message = _client_error(lambda: idstore.describe_group(IdentityStoreId=malformed_store_id, GroupId=group_id))
    assert code == "ValidationException", (
        f"DescribeGroup with a malformed IdentityStoreId {malformed_store_id!r} returned "
        f"error code {code!r}, expected \"ValidationException\""
    )
    assert message == (
        f"1 validation error detected: Value '{malformed_store_id}' at 'identityStoreId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        r"(arn:aws(-[a-z]{1,5}){0,3}:identitystore::\d{12}:identitystore/)?(d-[0-9a-f]{10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    ), (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # Positive control: the same GroupId, described against the REAL store, still succeeds.
    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert described["GroupId"] == group_id, (
        f"DescribeGroup against the real store {store_id!r} returned GroupId "
        f"{described['GroupId']!r}, expected {group_id!r}"
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
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
