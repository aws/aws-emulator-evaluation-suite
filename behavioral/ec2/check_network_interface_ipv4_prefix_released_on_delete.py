"""network-interface-ipv4-prefix-released-on-delete."""
from __future__ import annotations

import ipaddress

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-interface-ipv4-prefix-released-on-delete"
GROUP = "prefix-delegation"
SERVICES = ["ec2"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own
    not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _other_free_prefix(subnet_cidr: str, exclude: str) -> str:
    """A /28 block of subnet_cidr other than its reserved first block and exclude."""
    blocks = list(ipaddress.ip_network(subnet_cidr).subnets(new_prefix=28))
    for block in blocks[1:]:
        if str(block) != exclude:
            return str(block)
    raise AssertionError(f"no alternate /28 block in {subnet_cidr} besides {exclude!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A network interface's IPv4 prefix is refused to a second interface while assigned, and
    becomes assignable again, with no partial interface left behind, once the holder is deleted.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-prefdel-")
    subnet_cidr = "10.240.1.0/24"

    vpc_id = ec2.create_vpc(
        CidrBlock="10.240.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_cidr,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))

    # Pin each interface's primary address inside the subnet's reserved-adjacent first /28 block
    # (never auto-assigned as a prefix), so the free /28 picked for eni2 below cannot collide with
    # a primary address AWS placed on its own.
    eni1 = ec2.create_network_interface(
        SubnetId=subnet_id,
        PrivateIpAddress="10.240.1.4",
        Ipv4PrefixCount=1,
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": name}]}],
    )["NetworkInterface"]
    eni1_id = eni1["NetworkInterfaceId"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni1_id),
                  "InvalidNetworkInterfaceID.NotFound")
    )

    prefixes1 = eni1.get("Ipv4Prefixes", [])
    assert len(prefixes1) == 1, f"expected exactly one auto-assigned prefix, got {prefixes1!r}"
    prefix1 = prefixes1[0]["Ipv4Prefix"]
    prefix1_net = ipaddress.ip_network(prefix1)
    assert prefix1_net.prefixlen == 28, f"expected a /28 prefix, got {prefix1!r}"
    assert prefix1_net.subnet_of(ipaddress.ip_network(subnet_cidr)), (
        f"auto-assigned prefix {prefix1} falls outside subnet CIDR {subnet_cidr}"
    )

    described1 = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni1_id])["NetworkInterfaces"][0]
    described_prefixes1 = [p["Ipv4Prefix"] for p in described1.get("Ipv4Prefixes", [])]
    assert described_prefixes1 == [prefix1], (
        f"DescribeNetworkInterfaces returned prefixes {described_prefixes1!r}, expected [{prefix1!r}]"
    )

    # Negative: the same prefix cannot be assigned to a second interface while eni1 holds it.
    code, message = _error(
        lambda: ec2.create_network_interface(SubnetId=subnet_id, Ipv4Prefixes=[{"Ipv4Prefix": prefix1}])
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}: {message!r}"
    assert message == f"The prefix {prefix1} in subnet {subnet_id} overlaps with assigned prefixes.", (
        f"unexpected message {message!r}"
    )

    # Positive control: a different free /28 in the same subnet succeeds right away.
    other_prefix = _other_free_prefix(subnet_cidr, prefix1)
    eni2 = ec2.create_network_interface(
        SubnetId=subnet_id,
        PrivateIpAddress="10.240.1.5",
        Ipv4Prefixes=[{"Ipv4Prefix": other_prefix}],
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": name}]}],
    )["NetworkInterface"]
    eni2_id = eni2["NetworkInterfaceId"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni2_id),
                  "InvalidNetworkInterfaceID.NotFound")
    )
    eni2_prefixes = [p["Ipv4Prefix"] for p in eni2.get("Ipv4Prefixes", [])]
    assert eni2_prefixes == [other_prefix], f"expected eni2 to hold {other_prefix!r}, got {eni2_prefixes!r}"

    # The rejected duplicate-prefix call must not have left a partial interface in the subnet.
    survivors = ec2.describe_network_interfaces(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}])[
        "NetworkInterfaces"
    ]
    survivor_ids = sorted(e["NetworkInterfaceId"] for e in survivors)
    assert survivor_ids == sorted([eni1_id, eni2_id]), (
        f"expected exactly {sorted([eni1_id, eni2_id])!r} in {subnet_id!r}, found {survivor_ids!r}"
    )

    # Deleting eni1 releases its prefix: the same prefix becomes assignable again.
    ec2.delete_network_interface(NetworkInterfaceId=eni1_id)
    eni3 = ec2.create_network_interface(
        SubnetId=subnet_id,
        Ipv4Prefixes=[{"Ipv4Prefix": prefix1}],
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": name}]}],
    )["NetworkInterface"]
    eni3_id = eni3["NetworkInterfaceId"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni3_id),
                  "InvalidNetworkInterfaceID.NotFound")
    )
    eni3_prefixes = [p["Ipv4Prefix"] for p in eni3.get("Ipv4Prefixes", [])]
    assert eni3_prefixes == [prefix1], f"expected the freed prefix {prefix1!r} back on eni3, got {eni3_prefixes!r}"

    final = ec2.describe_network_interfaces(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}])[
        "NetworkInterfaces"
    ]
    final_ids = sorted(e["NetworkInterfaceId"] for e in final)
    assert final_ids == sorted([eni2_id, eni3_id]), (
        f"expected exactly {sorted([eni2_id, eni3_id])!r} in {subnet_id!r} after the delete, found {final_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
