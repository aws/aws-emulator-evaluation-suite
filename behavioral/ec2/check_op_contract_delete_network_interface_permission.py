"""op-contract-delete-network-interface-permission."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-network-interface-permission"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNetworkInterfacePermission of a non-existent permission id is rejected InvalidPermissionID.NotFound
    and nothing is listed for it; granting a permission to an ordinary account answers OperationNotPermitted."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-enip-")
    subnet_id = ctx.network().subnet_ids[0]

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec("network-interface", name)]
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    grant_code, grant_message = _error_of(
        lambda: ec2.create_network_interface_permission(
            NetworkInterfaceId=eni_id, AwsAccountId="111122223333", Permission="EIP-ASSOCIATE"
        )
    )
    assert grant_code == "OperationNotPermitted", f"expected OperationNotPermitted, got {grant_code!r}"
    assert grant_message == (
        "The account 111122223333 is not permitted to receive cross account permissions."
    ), grant_message
    granted = ec2.describe_network_interface_permissions(
        Filters=[{"Name": "network-interface-permission.network-interface-id", "Values": [eni_id]}]
    )["NetworkInterfacePermissions"]
    assert granted == [], f"expected no permission on {eni_id!r} after the refused grant, got {granted!r}"

    bogus_id = "eni-perm-00000000000000000"
    bogus_code, bogus_message = _error_of(lambda: ec2.delete_network_interface_permission(NetworkInterfacePermissionId=bogus_id))
    assert bogus_code == "InvalidPermissionID.NotFound", f"expected InvalidPermissionID.NotFound, got {bogus_code!r}"
    assert bogus_message == f"The ENI permission ID '{bogus_id}' does not exist", bogus_message
    assert _describe_permissions_after_delete(ec2, bogus_id) == [], f"{bogus_id} unexpectedly listed"


# ===== helpers =====
def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _describe_permissions_after_delete(ec2, perm_id: str) -> list:
    """DescribeNetworkInterfacePermissions raises InvalidPermissionID.NotFound (rather
    than returning an empty list) once the permission id no longer exists."""
    try:
        return ec2.describe_network_interface_permissions(NetworkInterfacePermissionIds=[perm_id])[
            "NetworkInterfacePermissions"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidPermissionID.NotFound":
            return []
        raise


def _error_of(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
