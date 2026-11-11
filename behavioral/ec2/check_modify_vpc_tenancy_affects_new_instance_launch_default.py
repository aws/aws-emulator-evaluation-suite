"""modify-vpc-tenancy-affects-new-instance-launch-default."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "modify-vpc-tenancy-affects-new-instance-launch-default"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcTenancy(InstanceTenancy='default') changes the VPC's default tenancy, so an instance
    launched later WITHOUT an explicit Placement.Tenancy inherits 'default', not the original 'dedicated'."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-tenancy-")
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/24",
        InstanceTenancy="dedicated",
        TagSpecifications=_tag_spec("vpc", name),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    created_tenancy = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["InstanceTenancy"]
    assert created_tenancy == "dedicated", (
        f"expected VPC created with InstanceTenancy='dedicated', got {created_tenancy!r}"
    )

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.93.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=_tag_spec("subnet", name),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    # Flip the VPC's default tenancy to 'default' BEFORE ever launching an
    # instance into it, so this check never incurs the Dedicated Instance
    # hourly surcharge.
    resp = ec2.modify_vpc_tenancy(VpcId=vpc_id, InstanceTenancy="default")
    assert resp["ReturnValue"] is True, f"expected ReturnValue=True, got {resp['ReturnValue']!r}"
    modified_tenancy = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["InstanceTenancy"]
    assert modified_tenancy == "default", (
        f"expected VPC InstanceTenancy='default' after ModifyVpcTenancy, got {modified_tenancy!r}"
    )

    image_id = _latest_amazon_linux_ami(ec2)
    run_resp = ec2.run_instances(
        ImageId=image_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec("instance", name),
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    # Terminate and wait for the instance to fully clear the subnet before
    # subnet/VPC teardown runs, so cleanup doesn't silently leak them behind
    # an ignored DependencyViolation.
    ctx.on_cleanup(lambda: _teardown_instance(ec2, instance_id))

    described = _poll_until(
        lambda: _describe_instance_tolerant(ec2, instance_id),
        lambda i: i is not None and i["State"]["Name"] in ("pending", "running"),
        timeout_s=120,
        interval_s=3,
    )
    # No Placement.Tenancy was specified at launch: it must inherit the VPC's
    # NEW default tenancy, not the tenancy the VPC was created with.
    actual_tenancy = described["Placement"]["Tenancy"]
    assert actual_tenancy == "default", (
        f"expected newly launched instance to inherit Placement.Tenancy='default', "
        f"got {actual_tenancy!r}"
    )


# ===== helpers =====

def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _latest_amazon_linux_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _ignore_error(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidInstanceID.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
        ):
            raise


def _describe_instance_tolerant(ec2, instance_id: str) -> dict[str, Any] | None:
    # DescribeInstances can transiently answer InvalidInstanceID.NotFound for a
    # just-launched instance ID before it becomes visible; treat that as "not
    # yet visible" rather than a failure.
    from botocore.exceptions import ClientError

    try:
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
            return None
        raise
    if not reservations or not reservations[0]["Instances"]:
        return None
    return reservations[0]["Instances"][0]


def _teardown_instance(ec2, instance_id: str) -> None:
    _ignore_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
            "Instances"
        ][0]["State"]["Name"],
        lambda state: state == "terminated",
        timeout_s=180,
        interval_s=5,
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


# A resource in this VPC deletes asynchronously, so its ENIs can hold the subnet or VPC and an
# immediate delete fails with DependencyViolation. Wait (bounded) for the ENIs to go, retry that one
# code in the same window, then raise naming the ENIs still attached; every other error propagates.
# The window is shared by all of one check's network deletes and fits the 900 s cleanup budget.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
