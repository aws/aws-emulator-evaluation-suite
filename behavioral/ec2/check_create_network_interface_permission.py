"""create-network-interface-permission."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-interface-permission"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNetworkInterfacePermission refuses a grantee account that is not enabled for
    cross-account ENI permissions, and an unknown network interface ID; neither leaves a grant.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-enip-")
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    subnet_id = _default_subnet_id(ec2, vpc_id, ctx=ctx)
    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": name}]}],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    grantee_account = "111122223333"
    code, message = _client_error(
        lambda: ec2.create_network_interface_permission(
            NetworkInterfaceId=eni_id,
            AwsAccountId=grantee_account,
            Permission="INSTANCE-ATTACH",
        )
    )
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted, got {code!r}"
    expected_refusal = f"The account {grantee_account} is not permitted to receive cross account permissions."
    assert message == expected_refusal, f"expected message {expected_refusal!r}, got {message!r}"

    granted = ec2.describe_network_interface_permissions(
        Filters=[{"Name": "network-interface-permission.network-interface-id", "Values": [eni_id]}]
    )["NetworkInterfacePermissions"]
    assert granted == [], f"expected no permission recorded on {eni_id!r} after the refusal, got {granted!r}"

    code, message = _client_error(
        lambda: ec2.create_network_interface_permission(
            NetworkInterfaceId="eni-00000000000000000",
            AwsAccountId=grantee_account,
            Permission="INSTANCE-ATTACH",
        )
    )
    assert code == "InvalidNetworkInterfaceID.NotFound", f"expected InvalidNetworkInterfaceID.NotFound, got {code!r}"
    expected_message = "The interface ID 'eni-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn() and return its error (code, message); an unexpected success raises.

    ParamValidationError is left uncaught: the request never reached AWS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        return vpcs[0]["VpcId"]
    raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")


def _default_subnet_id(ec2, vpc_id, *, ctx):
    subs = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subs:
        raise RuntimeError(f"no subnet of the run's shared network is available in VPC {vpc_id}")
    return subs[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
