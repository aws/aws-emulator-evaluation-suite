"""concurrent-capacity-reservation-modify-race-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-capacity-reservation-modify-race-single-winner"
GROUP = "concurrency"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent ModifyCapacityReservation calls with conflicting capacities: exactly one wins,
    the other gets CapacityReservationPending, and the persisted capacity is the winner's value.
    Where the feature is not enabled, both get OperationNotPermitted and no reservation persists."""
    elbv2 = ctx.client("elbv2")
    arn = _create_alb(ctx)

    def _attempt(units: int):
        try:
            resp = elbv2.modify_capacity_reservation(
                LoadBalancerArn=arn, MinimumLoadBalancerCapacity={"CapacityUnits": units}
            )
            return ("ok", units, resp["MinimumLoadBalancerCapacity"]["CapacityUnits"])
        except ClientError as e:
            return ("error", units, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_attempt, units) for units in (100, 200)]
        results = [f.result() for f in futures]

    if all(r[0] == "error" and r[2] == "OperationNotPermitted" for r in results):
        # ALB minimum capacity reservation needs AWS Support enablement; without it the gate
        # rejects both racers before any pending state, so nothing must persist.
        not_permitted = (
            "This AWS account does not support configuring minimum load balancer capacity "
            "reservation. For more information, please contact AWS Support."
        )
        for r in results:
            assert r[3] == not_permitted, f"unexpected OperationNotPermitted message, got {results}"
        described = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
        assert not described.get("CapacityReservationState"), described
        assert not described.get("MinimumLoadBalancerCapacity"), described
        return

    oks = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]
    assert len(oks) == 1, f"expected exactly one winning racer, got {results}"
    assert len(errors) == 1, f"expected exactly one rejected racer, got {results}"
    assert errors[0][2] == "CapacityReservationPending", f"unexpected loser error, got {results}"

    winner_units = oks[0][2]
    described = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
    persisted_units = described["MinimumLoadBalancerCapacity"]["CapacityUnits"]
    assert persisted_units == winner_units, (
        f"expected persisted capacity to match the winning racer's own reported value "
        f"{winner_units}, got {persisted_units}"
    )


def _tags_kv() -> list[dict]:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-capres"},
    ]


def _setup_network(ctx) -> list[str]:
    """Subnets in >=2 AZs to create the load balancer in.

    Prefers the run's shared network; a freshly provisioned account may not have
    one (or may lack subnets in 2 AZs), so this falls back to a dedicated,
    tagged, self-cleaned VPC rather than failing outright.
    """
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:2]

    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-capres-vpc-")}],
    )
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    subnet_ids = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)[
            "Subnet"
        ]["SubnetId"]
        ec2.create_tags(Resources=[sid], Tags=_tags_kv())
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return subnet_ids


def _wait_for_lb_active(ctx, arn: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
        code = lb["State"]["Code"]
        if code == "active":
            return
        if code == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State']}")
        time.sleep(interval_s)
    raise AssertionError(f"load balancer did not become active within {timeout_s}s")


def _create_alb(ctx) -> str:
    elbv2 = ctx.client("elbv2")
    subnets = _setup_network(ctx)
    name = ctx.unique_name("sim2real-capres-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnets, Type="application", Tags=_tags_kv()
    )
    arn = resp["LoadBalancers"][0]["LoadBalancerArn"]

    def _cleanup() -> None:
        try:
            elbv2.modify_capacity_reservation(LoadBalancerArn=arn, ResetCapacityReservation=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise

    ctx.on_cleanup(_cleanup)
    _wait_for_lb_active(ctx, arn)
    return arn


# Teardown waits (bounded) for AWS-managed ENIs to leave: a load balancer, endpoint, cluster or
# instance in this VPC deletes asynchronously and its ENIs linger, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Retry that inside one window shared
# by all of a check's network deletes, then raise naming the ENIs still attached.
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
