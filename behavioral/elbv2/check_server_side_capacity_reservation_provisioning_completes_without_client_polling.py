"""server-side-capacity-reservation-provisioning-completes-without-client-polling."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-capacity-reservation-provisioning-completes-without-client-polling"
GROUP = "server-side"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One ModifyCapacityReservation moves each AZ from a transitional state to provisioned with at
    least 100 effective units, seen through read-only Describe polls; where the account lacks the
    feature it fails with OperationNotPermitted and AWS's exact message, and no reservation state appears."""
    elbv2 = ctx.client("elbv2")
    arn = _create_alb(ctx)

    try:
        elbv2.modify_capacity_reservation(
            LoadBalancerArn=arn, MinimumLoadBalancerCapacity={"CapacityUnits": 100}
        )
        refused = None
    except ClientError as e:
        refused = e.response["Error"]
    if refused is not None:
        assert refused["Code"] == "OperationNotPermitted", (
            f"unexpected error requesting capacity reservation: {refused}")
        assert refused.get("Message") == (
            "This AWS account does not support configuring minimum load balancer capacity reservation. "
            "For more information, please contact AWS Support."
        ), refused
        # This account is not enabled for ALB minimum-capacity-reservation (requires
        # AWS Support enablement). The server-side contract that IS checkable here:
        # a rejected request triggers no asynchronous provisioning work at all -- no
        # CapacityReservationState ever appears, even after waiting, with no further
        # client calls issued (bounded read-only polling, not a bare sleep).
        described = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
        assert not described.get("CapacityReservationState"), described
        assert not described.get("MinimumLoadBalancerCapacity"), described

        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            time.sleep(2.0)
            polled = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
            assert not polled.get("CapacityReservationState"), (
                f"reservation state appeared spontaneously after a rejected request: {polled}"
            )
            assert not polled.get("MinimumLoadBalancerCapacity"), polled
        return

    initial = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
    assert initial["CapacityReservationState"], "expected at least one per-AZ reservation state"
    initial_codes = {s["State"]["Code"] for s in initial["CapacityReservationState"]}
    assert initial_codes != {"provisioned"}, (
        f"expected a transitional state immediately after the request (provisioning takes real "
        f"time), got every AZ already 'provisioned': {initial_codes}"
    )

    # No further ModifyCapacityReservation calls below -- only read-only
    # DescribeCapacityReservation polls, waiting for the server's own
    # provisioning schedule to complete the pending -> provisioned move.
    final = _poll_capacity_reservation(
        ctx,
        arn,
        lambda d: bool(d["CapacityReservationState"])
        and all(s["State"]["Code"] == "provisioned" for s in d["CapacityReservationState"]),
        timeout_s=600.0,
        interval_s=15.0,
    )
    for state in final["CapacityReservationState"]:
        assert state["EffectiveCapacityUnits"] >= 100, (
            f"expected effective capacity >= the requested 100 units, got {state}"
        )
    assert final["MinimumLoadBalancerCapacity"]["CapacityUnits"] == 100, (
        f"expected the durable minimum to reflect the requested 100 units, got {final['MinimumLoadBalancerCapacity']}"
    )


def _tag_spec(ctx, resource_type: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-capres-{resource_type}-")}],
    }


def _find_reusable_vpc(ec2, *, ctx) -> list[str] | None:
    """Reuse any existing VPC that already spans >=2 AZs, instead of always provisioning a
    fresh one -- this check has no need for a dedicated VPC, and always creating one can
    exhaust the account's per-region VPC quota when many behavioral checks run back-to-back."""
    try:
        vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    except ClientError:
        return None
    for vpc in sorted(vpcs, key=lambda v: not v.get("IsDefault", False)):
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:2]
    return None


def _default_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    reused = _find_reusable_vpc(ec2, ctx=ctx)
    if reused:
        return reused

    vpc_id = ec2.create_vpc(CidrBlock="10.97.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    if len(azs) < 2:
        raise AssertionError(f"region does not have 2 available AZs to create subnets in: {azs}")
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.97.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
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
    subnets = _default_subnets(ctx)
    name = ctx.unique_name("sim2real-capres-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnets,
        Type="application",
        Scheme="internal",
        Tags=[{"Key": "Name", "Value": name}],
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


def _poll_capacity_reservation(ctx, arn: str, predicate, timeout_s: float = 300.0, interval_s: float = 10.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"capacity reservation state never satisfied predicate; last={last}")


# Load balancers delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry inside one shared window, then fail naming the ENIs left.
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
