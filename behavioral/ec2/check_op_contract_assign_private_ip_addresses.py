"""op-contract-assign-private-ip-addresses."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-assign-private-ip-addresses"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssignPrivateIpAddresses adds secondary private IPs to an ENI; a bogus ENI id is rejected."""
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _default_vpc_subnet(ctx)

    name = ctx.unique_name("sim2real-eni-")
    eni = ec2.create_network_interface(
        SubnetId=subnet_id,
        Description=name,
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": name}]}],
    )["NetworkInterface"]
    eni_id = eni["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))
    before_ips = {p["PrivateIpAddress"] for p in eni["PrivateIpAddresses"]}
    assert len(before_ips) == 1

    resp = ec2.assign_private_ip_addresses(NetworkInterfaceId=eni_id, SecondaryPrivateIpAddressCount=1)
    assigned = resp.get("AssignedPrivateIpAddresses", [])
    assert len(assigned) == 1, f"expected 1 newly assigned IP, got {assigned}"
    new_ip = assigned[0]["PrivateIpAddress"]
    assert new_ip not in before_ips

    described = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    after_ips = {p["PrivateIpAddress"] for p in described["PrivateIpAddresses"]}
    assert after_ips == before_ips | {new_ip}, f"secondary IP not reflected: {after_ips}"
    secondary_flags = {p["PrivateIpAddress"]: p["Primary"] for p in described["PrivateIpAddresses"]}
    assert secondary_flags[new_ip] is False, "newly assigned IP must not be marked Primary"

    code, message = _error_of(
        lambda: ec2.assign_private_ip_addresses(
            NetworkInterfaceId="eni-00000000000000000", SecondaryPrivateIpAddressCount=1
        )
    )
    assert code == "InvalidNetworkInterfaceID.NotFound", f"unexpected error code: {code}"
    assert message == "The networkInterface ID 'eni-00000000000000000' does not exist", message


def _error_of(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _default_vpc_subnet(ctx):
    # Reuse the run's shared network/subnet instead of creating a dedicated VPC: accounts
    # have a small per-region VPC quota and this check doesn't need a bespoke network, just
    # somewhere to hang an ENI.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return vpc_id, subnets[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
