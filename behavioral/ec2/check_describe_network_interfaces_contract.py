"""describe-network-interfaces-contract."""
from __future__ import annotations

import ipaddress

from behavioral_harness import tags

CHECK = "describe-network-interfaces-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeNetworkInterfaces finds a created ENI by filter and answers DryRunOperation, refuses NetworkInterfaceIds
    with MaxResults as InvalidParameterCombination, and after the delete answers InvalidNetworkInterfaceID.NotFound
    to a read and a second delete, each with its exact message.
    """
    ec2 = ctx.client("ec2")
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    cidr = _pick_free_subnet_cidr(ec2, vpc_id, prefix_len=28)
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr)["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=[
            {
                "ResourceType": "network-interface",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eni-")}],
            }
        ],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _delete_eni_idempotent(ec2, eni_id))

    resp = ec2.describe_network_interfaces(
        Filters=[{"Name": "network-interface-id", "Values": [eni_id]}]
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from describe_network_interfaces, got {status}"
    found = {eni["NetworkInterfaceId"]: eni for eni in resp["NetworkInterfaces"]}
    assert eni_id in found, f"expected {eni_id} in describe_network_interfaces result"
    assert found[eni_id]["SubnetId"] == subnet_id, (
        f"expected SubnetId {subnet_id!r}, got {found[eni_id]['SubnetId']!r}"
    )

    _assert_dry_run_ok(
        lambda: ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id], DryRun=True
        )
    )

    # The API explicitly documents: "You cannot specify [MaxResults] and the network
    # interface IDs parameter in the same request."
    code, message = _error(
        lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id], MaxResults=5)
    )
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination, got {code!r}"
    )
    expected = "The parameter NetworkInterfaceIds cannot be used with the parameter MaxResults"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- delete proves gone and unusable: an independent read and a second delete
    # both hit the specific not-found code, never a resurrection or a quiet no-op ---
    ec2.delete_network_interface(NetworkInterfaceId=eni_id)

    read_code, read_message = _error(lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id]))
    assert read_code == "InvalidNetworkInterfaceID.NotFound", (
        f"expected a deleted ENI's own id to read back as InvalidNetworkInterfaceID.NotFound, "
        f"got {read_code!r}"
    )
    expected = f"The networkInterface ID '{eni_id}' does not exist"
    assert read_message == expected, f"expected message {expected!r}, got {read_message!r}"

    still_in_filter = ec2.describe_network_interfaces(
        Filters=[{"Name": "network-interface-id", "Values": [eni_id]}]
    )["NetworkInterfaces"]
    assert still_in_filter == [], (
        f"expected the deleted ENI to no longer match its own id filter, got {still_in_filter}"
    )

    redelete_code, redelete_message = _error(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))
    assert redelete_code == "InvalidNetworkInterfaceID.NotFound", (
        f"expected a second delete of an already-deleted ENI to fail as not-found, "
        f"got {redelete_code!r}"
    )
    expected = f"The networkInterface ID '{eni_id}' does not exist"
    assert redelete_message == expected, f"expected message {expected!r}, got {redelete_message!r}"


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        return vpcs[0]["VpcId"]
    raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")


def _pick_free_subnet_cidr(ec2, vpc_id, prefix_len=28):
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    associations = [
        a for a in vpc.get("CidrBlockAssociationSet", [])
        if a.get("CidrBlockState", {}).get("State") == "associated"
    ]
    vpc_nets = [ipaddress.ip_network(a["CidrBlock"]) for a in associations] or [
        ipaddress.ip_network(vpc["CidrBlock"])
    ]
    existing = [
        ipaddress.ip_network(s["CidrBlock"])
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    ]
    for vpc_net in vpc_nets:
        if vpc_net.prefixlen > prefix_len:
            continue
        for candidate in vpc_net.subnets(new_prefix=prefix_len):
            if not any(candidate.overlaps(e) for e in existing):
                return str(candidate)
    raise RuntimeError(f"no free /{prefix_len} CIDR block found in VPC {vpc_id}")


def _delete_eni_idempotent(ec2, eni_id):
    from botocore.exceptions import ClientError

    try:
        ec2.delete_network_interface(NetworkInterfaceId=eni_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")


def _assert_dry_run_ok(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
        assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
        return
    raise AssertionError("expected DryRunOperation error, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
