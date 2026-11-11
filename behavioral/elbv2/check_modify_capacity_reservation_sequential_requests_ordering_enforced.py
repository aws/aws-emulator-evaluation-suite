"""modify-capacity-reservation-sequential-requests-ordering-enforced."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-capacity-reservation-sequential-requests-ordering-enforced"
GROUP = "ordering"
SERVICES = ["elbv2"]


_NOT_PERMITTED = (
    "This AWS account does not support configuring minimum load balancer capacity reservation. "
    "For more information, please contact AWS Support."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second ModifyCapacityReservation while the first is pending is rejected with
    CapacityReservationPending and leaves 100 units in effect; once settled, 200 is accepted.
    Without the entitlement, both requests get OperationNotPermitted and leave no state."""
    elbv2 = ctx.client("elbv2")
    arn = _create_alb(ctx)

    baseline = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
    assert not baseline.get("CapacityReservationState"), (
        f"expected a freshly created load balancer to have no capacity reservation state, got {baseline}"
    )
    assert not baseline.get("MinimumLoadBalancerCapacity"), (
        f"expected a freshly created load balancer to have no reserved capacity, got {baseline}"
    )

    try:
        first = elbv2.modify_capacity_reservation(
            LoadBalancerArn=arn, MinimumLoadBalancerCapacity={"CapacityUnits": 100}
        )
    except ClientError as exc:
        first_err = exc.response["Error"]
        assert first_err["Code"] == "OperationNotPermitted", (
            f"unexpected error on first request: {first_err}"
        )
        assert first_err.get("Message") == _NOT_PERMITTED, f"unexpected refusal message: {first_err}"
        # Capacity reservations need AWS Support enablement; without it the gate applies to
        # every request, so the follow-up must not get a pending-state error instead.
        second_code, second_message = _error_code(
            lambda: elbv2.modify_capacity_reservation(
                LoadBalancerArn=arn, MinimumLoadBalancerCapacity={"CapacityUnits": 200}
            )
        )
        assert second_code == "OperationNotPermitted", (
            f"expected the immediately-following request to be rejected identically "
            f"with OperationNotPermitted, got {second_code!r}"
        )
        assert second_message == _NOT_PERMITTED, second_message
        described_after = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
        assert not described_after.get("CapacityReservationState"), (
            f"a rejected request must not leave reservation state behind: {described_after}"
        )
        assert not described_after.get("MinimumLoadBalancerCapacity"), (
            f"a rejected request must not leave a reserved capacity behind: {described_after}"
        )
        return

    assert first["MinimumLoadBalancerCapacity"]["CapacityUnits"] == 100, (
        f"positive control did not record the requested 100 units: {first}"
    )

    # Issued immediately, before any AZ of the first request can have left "pending".
    code, _message = _error_code(
        lambda: elbv2.modify_capacity_reservation(
            LoadBalancerArn=arn, MinimumLoadBalancerCapacity={"CapacityUnits": 200}
        )
    )
    assert code == "CapacityReservationPending", (
        f"expected CapacityReservationPending while the first request is still pending, got {code!r}"
    )

    described = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
    requested = described.get("MinimumLoadBalancerCapacity", {}).get("CapacityUnits")
    assert requested == 100, f"expected the original 100-unit request to still be in effect, got {requested}"

    # Per-AZ provisioning can take minutes, hence the 600 s bound.
    _poll_capacity_reservation(
        ctx,
        arn,
        lambda d: bool(d["CapacityReservationState"])
        and all(s["State"]["Code"] != "pending" for s in d["CapacityReservationState"]),
        timeout_s=600.0,
        interval_s=15.0,
    )
    second_now = elbv2.modify_capacity_reservation(
        LoadBalancerArn=arn, MinimumLoadBalancerCapacity={"CapacityUnits": 200}
    )
    assert second_now["MinimumLoadBalancerCapacity"]["CapacityUnits"] == 200, (
        f"the restored, identical request did not succeed with 200 units: {second_now}"
    )

    final = elbv2.describe_capacity_reservation(LoadBalancerArn=arn)
    assert final["MinimumLoadBalancerCapacity"]["CapacityUnits"] == 200, (
        f"expected the restored 200-unit request to be in effect, got {final}"
    )


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _get_or_create_subnets(ctx, count: int = 2) -> list[str]:
    """Reuse a VPC that spans >=count AZs if one exists, else create one; a default VPC may
    not exist."""
    ec2 = ctx.client("ec2")
    reused = _find_reusable_subnets(ec2, count, ctx=ctx)
    if reused:
        return reused

    vpc_id = ec2.create_vpc(
        CidrBlock="10.98.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-capres-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
        )["AvailabilityZones"]
    ]
    assert len(azs) >= count, f"region needs at least {count} available AZs for this check, got {azs}"

    subnet_ids = []
    for idx, az_name in enumerate(azs[:count]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.98.{idx}.0/24",
            AvailabilityZone=az_name,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-capres-subnet-")}],
            }],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _find_reusable_subnets(ec2, count: int, *, ctx) -> list[str] | None:
    try:
        vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    except ClientError:
        return None
    vpcs = sorted(vpcs, key=lambda v: not v.get("IsDefault", False))
    for vpc in vpcs:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= count:
            return sorted(by_az.values())[:count]
    return None


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
    subnets = _get_or_create_subnets(ctx)
    name = ctx.unique_name("sim2real-capres-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnets,
        Type="application",
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
