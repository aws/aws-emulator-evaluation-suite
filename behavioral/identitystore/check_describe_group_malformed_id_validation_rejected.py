"""describe-group-malformed-id-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-group-malformed-id-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeGroup rejects a GroupId that fails the resource-id pattern, before any existence check."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")

    malformed_group_id = "not-a-valid-resource-id!!"
    code, message = _client_error(
        lambda: idc.describe_group(IdentityStoreId=identity_store_id, GroupId=malformed_group_id)
    )
    assert code == "ValidationException", (
        f"expected DescribeGroup to reject malformed GroupId {malformed_group_id!r} with "
        f"ValidationException, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{malformed_group_id}' at 'groupId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        r"(arn:aws(-[a-z]{1,5}){0,3}:identitystore:::(user|group|membership)/)?([0-9a-f]{10}-|)[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}"
    ), (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # Positive control: DescribeGroup succeeds for a well-formed, existing GroupId.
    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))
    desc = idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    assert desc["DisplayName"] == display_name, (
        f"expected DescribeGroup({group_id!r}) DisplayName to be {display_name!r}, got "
        f"{desc.get('DisplayName')!r}"
    )


def _get_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if not instances:
        raise AssertionError(
            "No IAM Identity Center instance is enabled in this account/region "
            "(sso-admin ListInstances returned none); enable IAM Identity Center "
            "to provision an identity store for identitystore checks."
        )
    return instances[0]["IdentityStoreId"]


def _safe_delete_group(ctx, identity_store_id: str, group_id: str) -> None:
    idc = ctx.client("identitystore")
    try:
        idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
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
