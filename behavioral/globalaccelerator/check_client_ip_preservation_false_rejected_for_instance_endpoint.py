"""client-ip-preservation-false-rejected-for-instance-endpoint."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-ip-preservation-false-rejected-for-instance-endpoint"
GROUP = 'negative'
SERVICES = ['globalaccelerator']

# ===== helpers =====

_AL2023_SSM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _error(fn):
    """Return the (code, message) fn() raised; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry(fn, codes, budget=600.0, delay=10.0):
    """Call fn() until it stops raising one of `codes`; re-raise anything else."""
    deadline = time.monotonic() + budget
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.monotonic() > deadline:
                raise
            time.sleep(delay)


def _ec2_retry(fn):
    """Global Accelerator's client-IP-preservation ENI holds the subnet for several minutes."""
    return _retry(fn, codes=("DependencyViolation", "InvalidParameterDependency"), budget=900.0)


def _delete_accelerator_net(ga, arn):
    """Undo an accelerator completely: endpoint groups, listeners, disable, delete."""
    try:
        listeners, token = [], None
        while True:
            page = ga.list_listeners(AcceleratorArn=arn, **({"NextToken": token} if token else {}))
            listeners += page.get("Listeners", [])
            token = page.get("NextToken")
            if not token:
                break
        for listener in listeners:
            groups, gtoken = [], None
            while True:
                page = ga.list_endpoint_groups(
                    ListenerArn=listener["ListenerArn"],
                    **({"NextToken": gtoken} if gtoken else {}),
                )
                groups += page.get("EndpointGroups", [])
                gtoken = page.get("NextToken")
                if not gtoken:
                    break
            for group in groups:
                ga.delete_endpoint_group(EndpointGroupArn=group["EndpointGroupArn"])
            ga.delete_listener(ListenerArn=listener["ListenerArn"])
        ga.update_accelerator(AcceleratorArn=arn, Enabled=False)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "AcceleratorNotFoundException":
            raise
        return
    _retry(
        lambda: ga.delete_accelerator(AcceleratorArn=arn),
        codes=("AcceleratorNotDisabledException", "TransactionInProgressException"),
        budget=600.0,
    )


def _instance_endpoint(ctx, ec2, ssm):
    """One running t3.micro in a VPC with an internet gateway — a registrable GA endpoint."""
    want = "t3.micro"
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [want]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available AZ in {ctx.region!r} offers {want!r}"
    ami = ssm.get_parameter(Name=_AL2023_SSM)["Parameter"]["Value"]

    name = ctx.unique_name("sim2real-behav-ga-")
    tag_spec = [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": CHECK}]
    vpc = ec2.create_vpc(
        CidrBlock="10.63.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ec2_retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc)))
    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tag_spec}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _ec2_retry(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(
        lambda: _ec2_retry(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw, VpcId=vpc))
    )
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.63.1.0/24",
        AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _ec2_retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet)))
    sg = ec2.create_security_group(
        GroupName=name,
        Description=f"sim2real global-accelerator endpoint {name}",
        VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag_spec}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _ec2_retry(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg)))
    instance = ec2.run_instances(
        ImageId=ami,
        InstanceType=want,
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[
            {
                "DeviceIndex": 0,
                "AssociatePublicIpAddress": True,
                "SubnetId": subnet,
                "Groups": [sg],
                "DeleteOnTermination": True,
            }
        ],
        TagSpecifications=[{"ResourceType": "instance", "Tags": tag_spec}],
    )["Instances"][0]["InstanceId"]

    def _terminate():
        ec2.terminate_instances(InstanceIds=[instance])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance], WaiterConfig={"Delay": 2, "MaxAttempts": 450}
        )

    ctx.on_cleanup(_terminate)
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    return instance


def _endpoints_of(ga, group):
    return ga.describe_endpoint_group(EndpointGroupArn=group)["EndpointGroup"][
        "EndpointDescriptions"
    ]


# ===== end helpers =====


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """Registering an EC2 instance endpoint with ClientIPPreservationEnabled=False is rejected and
    the endpoint group stays empty, because an instance endpoint always preserves the client IP;
    the same call with True is accepted."""
    ga = ctx.client("globalaccelerator")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    instance = _instance_endpoint(ctx, ec2, ssm)

    accelerator = ga.create_accelerator(
        Name=ctx.unique_name("sim2real-behav-ga-"),
        IpAddressType="IPV4",
        Enabled=False,
        IdempotencyToken=str(uuid.uuid4()),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Accelerator"]
    arn = accelerator["AcceleratorArn"]
    ctx.on_cleanup(lambda: _delete_accelerator_net(ga, arn))

    listener = ga.create_listener(
        AcceleratorArn=arn,
        PortRanges=[{"FromPort": 80, "ToPort": 80}],
        Protocol="TCP",
        IdempotencyToken=str(uuid.uuid4()),
    )["Listener"]["ListenerArn"]
    group = ga.create_endpoint_group(
        ListenerArn=listener,
        EndpointGroupRegion=ctx.region,
        TrafficDialPercentage=100.0,
        HealthCheckPort=80,
        HealthCheckProtocol="TCP",
        HealthCheckIntervalSeconds=30,
        ThresholdCount=3,
        IdempotencyToken=str(uuid.uuid4()),
    )["EndpointGroup"]["EndpointGroupArn"]

    code, message = _error(
        lambda: ga.update_endpoint_group(
            EndpointGroupArn=group,
            EndpointConfigurations=[
                {"EndpointId": instance, "Weight": 128, "ClientIPPreservationEnabled": False}
            ],
        )
    )
    assert code == "InvalidArgumentException", (
        f"registering EC2 instance {instance} with ClientIPPreservationEnabled=False returned "
        f"{code!r}, expected 'InvalidArgumentException'"
    )
    expected = "Client IP Preservation cannot be set to false for EC2 instances"
    assert message == expected, (
        f"registering EC2 instance {instance} with ClientIPPreservationEnabled=False returned "
        f"message {message!r}, expected {expected!r}"
    )
    assert _endpoints_of(ga, group) == [], (
        f"the rejected registration added the endpoint anyway: {_endpoints_of(ga, group)!r}"
    )

    # Positive control: the identical call with preservation enabled registers the same instance,
    # so the rejection is the False value and not an unregistrable instance.
    ga.update_endpoint_group(
        EndpointGroupArn=group,
        EndpointConfigurations=[
            {"EndpointId": instance, "Weight": 128, "ClientIPPreservationEnabled": True}
        ],
    )
    registered = _endpoints_of(ga, group)
    assert [e["EndpointId"] for e in registered] == [instance], (
        f"control: registering {instance} with preservation enabled left the endpoint group "
        f"holding {registered!r}"
    )
    assert registered[0]["ClientIPPreservationEnabled"] is True, (
        f"control: the registered endpoint reports ClientIPPreservationEnabled="
        f"{registered[0]['ClientIPPreservationEnabled']!r}, expected True"
    )

    # Every assertion is made; deregister now so the elastic network interface Global
    # Accelerator places in the subnet for client IP preservation starts being released before
    # teardown tries to delete that subnet.
    ga.update_endpoint_group(EndpointGroupArn=group, EndpointConfigurations=[])


# EC2 network teardown: AWS-managed ENIs outlive the delete of the resource that owns them, so
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc answer DependencyViolation until they go. Wait for
# the ENIs and retry that code inside one window shared by the check's network deletes.
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
