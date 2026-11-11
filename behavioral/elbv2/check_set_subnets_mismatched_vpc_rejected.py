"""set-subnets-mismatched-vpc-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-subnets-mismatched-vpc-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetSubnets with a subnet from another VPC fails with InvalidConfigurationRequest and the exact message and
    leaves the load balancer's subnets and VPC unchanged, while a same-VPC SetSubnets applies."""
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    vpc_a_id, subnets_a = _create_vpc_with_subnets(ctx, "10.104.0.0/16", count=2)
    vpc_b_id, subnets_b = _create_vpc_with_subnets(ctx, "10.105.0.0/16", count=1)

    lb_name = ctx.unique_name("sim2real-behav-lb-")
    lb = elbv2.create_load_balancer(
        Name=lb_name,
        Subnets=subnets_a,
        Scheme="internal",
        Type="application",
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    original_subnet_ids = sorted(
        az["SubnetId"] for az in elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["AvailabilityZones"]
    )

    # Pick a subnet from VPC A whose AZ differs from the VPC B subnet's AZ, so the
    # request satisfies the "at least 2 distinct AZs" rule and only violates VPC match.
    az_of_b = ec2.describe_subnets(SubnetIds=[subnets_b[0]])["Subnets"][0]["AvailabilityZone"]
    subnet_a_other_az = next(
        s["SubnetId"]
        for s in ec2.describe_subnets(SubnetIds=subnets_a)["Subnets"]
        if s["AvailabilityZone"] != az_of_b
    )

    def _set_bad() -> None:
        elbv2.set_subnets(LoadBalancerArn=lb_arn, Subnets=[subnet_a_other_az, subnets_b[0]])

    code, message = _error(_set_bad)
    # AWS rejects a cross-VPC subnet set with InvalidConfigurationRequest
    # (the subnets individually exist and have addresses available -- InvalidSubnet is
    # reserved for address-exhaustion/not-found cases -- but mixing VPCs is an invalid
    # configuration for the load balancer as a whole).
    assert code == "InvalidConfigurationRequest", f"expected InvalidConfigurationRequest, got {code}"
    expected_message = f"All subnets must belong to the same VPC: '{vpc_a_id}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the load balancer's subnets are unchanged (still VPC A's original set).
    current_subnet_ids = sorted(
        az["SubnetId"] for az in elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["AvailabilityZones"]
    )
    assert current_subnet_ids == original_subnet_ids, (
        f"subnets changed to {current_subnet_ids} despite the rejected SetSubnets call"
    )
    assert lb["VpcId"] == vpc_a_id, (
        f"load balancer VpcId is {lb['VpcId']!r}, expected the VPC A it was created in "
        f"({vpc_a_id!r})"
    )

    # Positive control: replacing with subnets from the SAME VPC succeeds.
    elbv2.set_subnets(LoadBalancerArn=lb_arn, Subnets=subnets_a)
    refreshed = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    refreshed_subnet_ids = sorted(az["SubnetId"] for az in refreshed["AvailabilityZones"])
    assert refreshed_subnet_ids == sorted(subnets_a), (
        f"same-VPC SetSubnets left subnets at {refreshed_subnet_ids}, expected "
        f"{sorted(subnets_a)} after the identical (same-VPC) call succeeded"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_vpc_with_subnets(ctx: Any, cidr: str, count: int) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:count]
    assert len(azs) >= count, "region needs enough available AZs for this check"

    base = cidr.rsplit(".", 2)[0]
    subnet_ids = []
    for idx, az_name in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"{base}.{idx}.0/24",
            AvailabilityZone=az_name,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}],
            }],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return vpc_id, subnet_ids


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
