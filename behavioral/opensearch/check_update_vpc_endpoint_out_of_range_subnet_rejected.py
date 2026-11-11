"""update-vpc-endpoint-out-of-range-subnet-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-vpc-endpoint-out-of-range-subnet-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """UpdateVpcEndpoint with a subnet from a different VPC is rejected with ValidationException
    and leaves the endpoint unchanged, while an update within the same VPC still succeeds.
    """
    ec2 = ctx.client("ec2")
    osc = ctx.client("opensearch")

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]

    vpc_a = _create_vpc(ctx, ec2, "10.90.0.0/16")
    subnet_a = _create_subnet(ctx, ec2, vpc_a, "10.90.1.0/24", az)
    sg_a = _create_sg(ctx, ec2, vpc_a, "sg-a")
    # Created before the domain so LIFO teardown deletes the endpoint and domain before this
    # group, rather than waiting on the endpoint's ENIs that still hold it.
    sg_a2 = _create_sg(ctx, ec2, vpc_a, "sg-a2")

    vpc_b = _create_vpc(ctx, ec2, "10.91.0.0/16")
    subnet_b = _create_subnet(ctx, ec2, vpc_b, "10.91.1.0/24", az)

    domain_name = ctx.unique_name("sim2real-uve-")[:28].rstrip("-")
    domain = osc.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        VPCOptions={"SubnetIds": [subnet_a], "SecurityGroupIds": [sg_a]},
    )
    domain_arn = domain["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))

    # CreateVpcEndpoint fails with ValidationException while the domain is still being
    # provisioned ("Unable to process request because the specified domain is currently
    # being modified"), so the domain must reach ACTIVE (Processing=False) first.
    _wait_domain_active(osc, domain_name)

    endpoint = osc.create_vpc_endpoint(
        DomainArn=domain_arn, VpcOptions={"SubnetIds": [subnet_a], "SecurityGroupIds": [sg_a]}
    )["VpcEndpoint"]
    endpoint_id = endpoint["VpcEndpointId"]
    ctx.on_cleanup(lambda: osc.delete_vpc_endpoint(VpcEndpointId=endpoint_id))
    _wait_endpoint_active(osc, endpoint_id)

    code = _error_code(
        lambda: osc.update_vpc_endpoint(
            VpcEndpointId=endpoint_id, VpcOptions={"SubnetIds": [subnet_b], "SecurityGroupIds": [sg_a]}
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"

    # Effect absent: the endpoint must still reference the ORIGINAL VPC A subnet.
    unchanged = osc.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert unchanged["VpcOptions"]["SubnetIds"] == [subnet_a], (
        f"rejected update mutated subnet: {unchanged['VpcOptions']!r}"
    )

    # Positive control: a legitimate update within the SAME VPC succeeds.
    osc.update_vpc_endpoint(
        VpcEndpointId=endpoint_id, VpcOptions={"SubnetIds": [subnet_a], "SecurityGroupIds": [sg_a, sg_a2]}
    )
    _wait_endpoint_active(osc, endpoint_id)

    # Terminal read: independent of the mutating call, at the destination.
    updated = osc.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert set(updated["VpcOptions"]["SecurityGroupIds"]) == {sg_a, sg_a2}, (
        f"legitimate update did not persist: {updated['VpcOptions']!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError("expected the call to fail, but it succeeded")


def _tag_spec(ctx, resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _create_vpc(ctx, ec2, cidr):
    name = ctx.unique_name("sim2real-uve-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=_tag_spec(ctx, "vpc", name))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _create_subnet(ctx, ec2, vpc_id, cidr, az):
    name = ctx.unique_name("sim2real-uve-subnet-")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=az, TagSpecifications=_tag_spec(ctx, "subnet", name)
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return subnet_id


def _create_sg(ctx, ec2, vpc_id, suffix):
    name = ctx.unique_name(f"sim2real-uve-{suffix}-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral check",
        VpcId=vpc_id,
        TagSpecifications=_tag_spec(ctx, "security-group", name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return sg_id


def _wait_endpoint_active(osc, endpoint_id, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ep = osc.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
        if ep["Status"] == "ACTIVE":
            return ep
        if ep["Status"] == "CREATE_FAILED":
            raise AssertionError("vpc endpoint failed to create")
        time.sleep(interval_s)
    raise AssertionError(f"vpc endpoint {endpoint_id} did not become ACTIVE within {timeout_s}s")


def _wait_domain_active(osc, domain_name, timeout_s=1800.0, interval_s=30.0):
    # AWS documents domain creation as typically taking 15-30 minutes. Rely on
    # DomainProcessingStatus == "Active" (Created/Processing booleans can flip to
    # "not processing" slightly before the domain is actually ready to accept a VPC
    # endpoint, which then 400s with "domain is currently being created").
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        processing_status = status.get("DomainProcessingStatus")
        if processing_status is not None:
            if processing_status == "Active":
                return status
        elif not status.get("Processing", True) and status.get("Created", False):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} did not become active within {timeout_s}s")


# Network teardown waits (bounded) for AWS-managed ENIs to leave and retries DependencyViolation:
# resources in the VPC delete asynchronously, so an immediate delete of the subnet, security group
# or VPC fails while their ENIs remain. The window is shared by all of one check's network deletes.
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
