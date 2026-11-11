"""fleet-stack-association-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "fleet-stack-association-lifecycle"
GROUP = "lifecycle"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """AssociateFleet/DisassociateFleet flip membership visible via List*Associated*."""
    appstream = ctx.client("appstream")
    vpc = _create_vpc(ctx)

    fleet_name = ctx.unique_name("sim2real-appstream-fleet-")
    _retry_role_propagation(
        lambda: appstream.create_fleet(
            Name=fleet_name,
            InstanceType="stream.standard.small",
            FleetType="ELASTIC",
            Platform="WINDOWS_SERVER_2019",
            MaxConcurrentSessions=5,
            VpcConfig={"SubnetIds": vpc["subnet_ids"]},
        )
    )
    ctx.on_cleanup(lambda: appstream.delete_fleet(Name=fleet_name))

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    appstream.create_stack(Name=stack_name)
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=stack_name))

    appstream.associate_fleet(FleetName=fleet_name, StackName=stack_name)

    fleets_for_stack = appstream.list_associated_fleets(StackName=stack_name)["Names"]
    assert fleet_name in fleets_for_stack, (
        f"expected {fleet_name!r} in ListAssociatedFleets(StackName={stack_name!r}) "
        f"after AssociateFleet, got {fleets_for_stack!r}"
    )

    stacks_for_fleet = appstream.list_associated_stacks(FleetName=fleet_name)["Names"]
    assert stack_name in stacks_for_fleet, (
        f"expected {stack_name!r} in ListAssociatedStacks(FleetName={fleet_name!r}) "
        f"after AssociateFleet, got {stacks_for_fleet!r}"
    )

    appstream.disassociate_fleet(FleetName=fleet_name, StackName=stack_name)

    fleets_after = appstream.list_associated_fleets(StackName=stack_name)["Names"]
    assert fleet_name not in fleets_after, (
        f"expected {fleet_name!r} absent from ListAssociatedFleets(StackName={stack_name!r}) "
        f"after DisassociateFleet, still present: {fleets_after!r}"
    )
    stacks_after = appstream.list_associated_stacks(FleetName=fleet_name)["Names"]
    assert stack_name not in stacks_after, (
        f"expected {stack_name!r} absent from ListAssociatedStacks(FleetName={fleet_name!r}) "
        f"after DisassociateFleet, still present: {stacks_after!r}"
    )


# ===== helpers =====
def _retry_role_propagation(fn, timeout_s: float = 90.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_vpc(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    cidr = "10.211.0.0/24"
    vpc = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-appstream-vpc-")}],
            }
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        state = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if state == "available":
            break
        time.sleep(1)

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.211.0.{i * 128}/25",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-appstream-subnet-")}],
                }
            ],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_id": subnet_ids[0], "subnet_ids": subnet_ids}


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that would leak the
# VPC while the check passed. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's 900s cleanup budget here.
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
