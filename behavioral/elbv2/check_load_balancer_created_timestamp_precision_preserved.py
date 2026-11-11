"""load-balancer-created-timestamp-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "load-balancer-created-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The CreatedTime returned by CreateLoadBalancer comes back unchanged, at full precision,
    on repeated DescribeLoadBalancers calls."""
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    subnets = _provision_two_az_subnets(ctx, ec2)

    name = _short_name(ctx, "lb")
    created = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnets,
        Scheme="internal",
        Type="application",
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )["LoadBalancers"][0]
    lb_arn = created["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_load_balancer(elbv2, lb_arn))

    created_time = created["CreatedTime"]

    # Spread the describes over a short window so a value regenerated from "now" would differ.
    seen = []
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and len(seen) < 3:
        described = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        seen.append(described["CreatedTime"])
        time.sleep(1.5)

    assert len(seen) >= 2, "could not obtain repeated describes within the poll window"
    for i, ts in enumerate(seen):
        assert ts == created_time, (
            f"describe #{i} CreatedTime {ts!r} != create-response CreatedTime {created_time!r}"
        )


# ===== helpers =====
def _short_name(ctx, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-").replace("_", "-")
    return name[:32].rstrip("-")


def _provision_two_az_subnets(ctx, ec2) -> list[str]:
    """Create a dedicated VPC + 2 subnets in different AZs; a default VPC may not exist."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.183.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "sim2real:check", "Value": CHECK}]}
        ],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs if az["State"] == "available"][:2]
    if len(az_names) < 2:
        raise AssertionError(f"region has fewer than 2 available AZs required to create an ALB: {az_names!r}")

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.183.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "sim2real:check", "Value": CHECK}]}
            ],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_subnet(ec2, sid))
    return subnet_ids


def _delete_load_balancer(elbv2, lb_arn: str) -> None:
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except elbv2.exceptions.LoadBalancerNotFoundException:
            return
        time.sleep(2)


def _delete_subnet(ec2, subnet_id: str) -> None:
    try:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _delete_vpc(ec2, vpc_id: str) -> None:
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


# Resources in this VPC (load balancers, endpoints, functions, ...) delete asynchronously and
# leave ENIs behind, so network deletes answer DependencyViolation for a while. Wait, bounded,
# for those ENIs to go, then raise naming any still attached. The window is shared by all of a
# check's network deletes.
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
