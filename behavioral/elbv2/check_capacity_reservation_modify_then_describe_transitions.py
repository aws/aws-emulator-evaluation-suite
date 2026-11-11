"""capacity-reservation-modify-then-describe-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-reservation-modify-then-describe-transitions"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCapacityReservation sets a minimum capacity that DescribeCapacityReservation reflects
    over time -- or, on an account without the ALB minimum-capacity-reservation entitlement, is
    refused, and the reservation must never appear, even transiently, after the refusal."""
    elbv2 = ctx.client("elbv2")

    vpc_id, subnet_ids = _vpc_two_subnets(ctx)
    sg_id = _new_security_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, subnet_ids, sg_id)  # positive control: elbv2/ec2 plumbing works
    # release the reservation on cleanup before the load balancer is torn down; an unentitled
    # account has nothing to release, so OperationNotPermitted here is expected, not a leak
    ctx.on_cleanup(
        _teardown(
            lambda: elbv2.modify_capacity_reservation(LoadBalancerArn=lb_arn, ResetCapacityReservation=True),
            "LoadBalancerNotFound",
            "OperationNotPermitted",
        )
    )

    baseline = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert baseline.get("CapacityReservationState", []) == [], (
        f"expected no capacity reservation state before any ModifyCapacityReservation, got {baseline}"
    )

    try:
        modify_resp = elbv2.modify_capacity_reservation(
            LoadBalancerArn=lb_arn, MinimumLoadBalancerCapacity={"CapacityUnits": 100}
        )
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "OperationNotPermitted" and "does not support" in error.get("Message", ""):
            _assert_reservation_withheld(elbv2, lb_arn)
            return
        raise

    assert modify_resp["MinimumLoadBalancerCapacity"]["CapacityUnits"] == 100, (
        f"expected MinimumLoadBalancerCapacity.CapacityUnits == 100 right after ModifyCapacityReservation, "
        f"got {modify_resp.get('MinimumLoadBalancerCapacity')}"
    )

    described = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert described["MinimumLoadBalancerCapacity"]["CapacityUnits"] == 100, (
        f"expected MinimumLoadBalancerCapacity.CapacityUnits == 100 on the independent describe, "
        f"got {described.get('MinimumLoadBalancerCapacity')}"
    )
    assert described["CapacityReservationState"], "expected per-AZ capacity reservation state entries"

    deadline = time.monotonic() + 240.0
    final = described
    final_codes = None
    while time.monotonic() < deadline:
        final = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
        final_codes = {s["State"]["Code"] for s in final["CapacityReservationState"]}
        if final_codes == {"provisioned"}:
            break
        assert "failed" not in final_codes, f"capacity reservation entered 'failed' state: {final}"
        time.sleep(2.0)
    else:
        raise AssertionError(
            f"capacity reservation did not converge to 'provisioned' within 240s (last={final_codes})",
        )

    for state in final["CapacityReservationState"]:
        assert state["EffectiveCapacityUnits"] >= 100, (
            f"expected EffectiveCapacityUnits >= the requested 100 units, got {state}"
        )


def _assert_reservation_withheld(elbv2, lb_arn: str) -> None:
    """This account is not entitled to ALB minimum-capacity-reservation (requires an AWS Support
    grant): ModifyCapacityReservation was refused with OperationNotPermitted. That refusal is the
    contract this check can assert here -- no reservation state may appear, even transiently and
    even after waiting, since the rejected request must not have started any async provisioning."""
    described = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert not described.get("CapacityReservationState"), (
        f"expected no capacity reservation state after a rejected ModifyCapacityReservation, got {described}"
    )
    assert not described.get("MinimumLoadBalancerCapacity"), (
        f"expected no MinimumLoadBalancerCapacity after a rejected ModifyCapacityReservation, got {described}"
    )

    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        time.sleep(2.0)
        polled = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
        assert not polled.get("CapacityReservationState"), (
            f"capacity reservation state appeared spontaneously after a rejected request: {polled}"
        )
        assert not polled.get("MinimumLoadBalancerCapacity"), (
            f"MinimumLoadBalancerCapacity appeared spontaneously after a rejected request: {polled}"
        )


# ===== helpers (self-contained) =====
def _teardown(undo, *not_found: str):
    """Run ``undo()``; only the given not-found codes mean the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _tag_spec(ctx, resource_type: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-elbv2-{resource_type}-")}],
    }


def _find_reusable_vpc(ec2, *, ctx):
    """Reuse an existing VPC that already has subnets spanning >=2 AZs, instead of always
    provisioning a fresh one -- this check has no need for a dedicated VPC, and always creating
    one can exhaust the account's per-region VPC quota when many behavioral checks run
    back-to-back (VpcLimitExceeded)."""
    try:
        vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    except ClientError:
        return None
    vpcs = sorted(vpcs, key=lambda v: not v.get("IsDefault", False))
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) < 2:
            continue
        return vpc_id, list(by_az.values())[:2]
    return None


def _vpc_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    reused = _find_reusable_vpc(ec2, ctx=ctx)
    if reused:
        return reused

    vpc_id = ec2.create_vpc(CidrBlock="10.97.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.97.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            _teardown(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid), "InvalidSubnetID.NotFound")
        )
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _new_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-elbv2-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real elbv2 behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(
        _teardown(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound")
    )
    return sg_id


def _create_alb(ctx, subnet_ids, sg_id: str, scheme: str = "internal") -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme=scheme, Type="application"
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn), "LoadBalancerNotFound"))
    waiter = elbv2.get_waiter("load_balancer_available")
    waiter.wait(LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return lb_arn


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc can fail with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached. Every other error propagates. Teardown-only: nothing run()
# executes calls this, so it cannot change the verdict. The window is shared by all of one check's
# network deletes.
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
