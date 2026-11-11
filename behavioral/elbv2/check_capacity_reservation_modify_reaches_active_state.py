"""capacity-reservation-modify-reaches-active-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-reservation-modify-reaches-active-state"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCapacityReservation drives every AZ's reservation to 'provisioned' with the requested
    capacity, or, without the Support entitlement, is refused and never takes effect."""
    elbv2 = ctx.client("elbv2")
    _vpc_id, subnet_ids = _default_vpc_two_az_subnets(ctx)
    lb_arn = _create_alb(ctx, subnet_ids)

    before = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert before.get("MinimumLoadBalancerCapacity") in (None, {}), (
        f"expected a freshly created load balancer to have no reserved capacity, got {before}"
    )
    assert before.get("CapacityReservationState", []) == [], (
        f"expected a freshly created load balancer to have no capacity reservation state, got {before}"
    )

    def _reset():
        try:
            elbv2.modify_capacity_reservation(LoadBalancerArn=lb_arn, ResetCapacityReservation=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise

    ctx.on_cleanup(_reset)

    try:
        modified = elbv2.modify_capacity_reservation(
            LoadBalancerArn=lb_arn, MinimumLoadBalancerCapacity={"CapacityUnits": 100}
        )
    except Exception as err:
        from botocore.exceptions import ClientError

        if (
            isinstance(err, ClientError)
            and err.response["Error"]["Code"] == "OperationNotPermitted"
            and "does not support" in err.response["Error"].get("Message", "")
        ):
            # Minimum capacity needs an AWS Support entitlement; unentitled accounts get this
            # refusal for an otherwise healthy, active ALB.
            after = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
            assert after.get("MinimumLoadBalancerCapacity") in (None, {}), after
            assert after.get("CapacityReservationState", []) == [], after
            return
        raise
    assert modified["MinimumLoadBalancerCapacity"]["CapacityUnits"] == 100, (
        f"expected the accepted request to record 100 units, got {modified}"
    )
    assert len(modified["CapacityReservationState"]) == len(subnet_ids), (
        f"expected one capacity reservation state per AZ ({len(subnet_ids)}), got {modified}"
    )
    for zone_state in modified["CapacityReservationState"]:
        # The response that starts the transition may still be in flight; the poll below pins provisioned.
        assert zone_state["State"]["Code"] != "failed", f"capacity reservation failed: {zone_state}"

    final = _poll_until_or_skip(
        lambda: elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn),
        lambda resp: resp["MinimumLoadBalancerCapacity"]["CapacityUnits"] == 100
        and all(z["State"]["Code"] == "provisioned" for z in resp["CapacityReservationState"]),
        timeout_s=420,
        interval_s=15,
    )
    assert final["MinimumLoadBalancerCapacity"]["CapacityUnits"] == 100, (
        f"expected the settled reservation to still be 100 units, got {final}"
    )
    assert len(final["CapacityReservationState"]) == len(subnet_ids), (
        f"expected one settled capacity reservation state per AZ ({len(subnet_ids)}), got {final}"
    )
    for zone_state in final["CapacityReservationState"]:
        assert zone_state["State"]["Code"] == "provisioned", (
            f"expected every zone to settle at provisioned, got {zone_state}"
        )
        assert zone_state["EffectiveCapacityUnits"] >= 0, (
            f"expected a non-negative effective capacity, got {zone_state}"
        )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _poll_until_or_skip(probe, predicate, timeout_s=60.0, interval_s=3.0):
    # 'provisioned' is the terminal CapacityReservationStatus code; there is no 'active' code.
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"capacity reservation did not reach 'provisioned' within {timeout_s}s (last: {last!r}); "
        "this is a long-horizon async transition on real AWS",
    )


def _default_vpc_two_az_subnets(ctx):
    

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span at least 2 availability zones")
    subnet_ids = list(by_az.values())[:2]
    return vpc_id, subnet_ids


def _create_alb(ctx, subnet_ids) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-lb-cap-")[:32]
    lb = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Type="application", Scheme="internal",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _cleanup():
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code in ("active", "active_impaired"),
        timeout_s=180,
        interval_s=5,
    )
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
