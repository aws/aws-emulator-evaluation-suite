"""zonal-shift-expires-after-min-duration."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "zonal-shift-expires-after-min-duration"
GROUP = "state"
SERVICES = ["arc-zonal-shift"]


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/arc-zonal-shift/latest/api/API_StartZonalShift.html
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A customer-started zonal shift with the minimum expiresIn ("1m") autonomously
    transitions ACTIVE -> EXPIRED once its expiryTime passes, and the resource's applied
    weight for the AZ is restored once the shift is no longer active."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, away_from = _create_nlb_managed_resource(ctx)

    shift = arc.start_zonal_shift(
        resourceIdentifier=lb_arn,
        awayFrom=away_from,
        expiresIn="1m",
        comment="sim2real-min-duration-shift",
    )
    shift_id = shift["zonalShiftId"]
    ctx.on_cleanup(lambda: _cancel_if_active(arc, shift_id))
    assert shift["status"] == "ACTIVE"

    early_deadline = time.monotonic() + 20.0
    while time.monotonic() < early_deadline:
        still_active = next(
            i
            for i in arc.list_zonal_shifts(resourceIdentifier=lb_arn)["items"]
            if i["zonalShiftId"] == shift_id
        )
        assert still_active["status"] == "ACTIVE", (
            f"expected shift to still be ACTIVE within its 1m expiresIn, "
            f"got {still_active['status']!r} — it must not expire before its minimum duration"
        )
        time.sleep(5)

    # ListZonalShifts lists ACTIVE shifts unless a status is named, so the expired shift is read
    # through status="EXPIRED", and must also have left the ACTIVE listing.
    final_status = _poll_until(
        lambda: arc.list_zonal_shifts(resourceIdentifier=lb_arn, status="EXPIRED")["items"],
        lambda items: any(i["zonalShiftId"] == shift_id for i in items),
        timeout_s=360.0,
        interval_s=10.0,
    )
    matched = next(i for i in final_status if i["zonalShiftId"] == shift_id)
    assert matched["status"] == "EXPIRED", f"expected EXPIRED, got {matched['status']!r}"
    # The unfiltered listing converges on the expiry a little after the EXPIRED one does.
    _poll_until(
        lambda: [
            i["zonalShiftId"] for i in arc.list_zonal_shifts(resourceIdentifier=lb_arn)["items"]
            if i["status"] == "ACTIVE"
        ],
        lambda active_ids: shift_id not in active_ids,
        timeout_s=120.0,
        interval_s=5.0,
    )

    weights_after = _poll_until(
        lambda: arc.get_managed_resource(resourceIdentifier=lb_arn)["appliedWeights"],
        lambda w: w.get(away_from) == 1.0,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert weights_after[away_from] == 1.0


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _cancel_if_active(arc, shift_id):
    try:
        arc.cancel_zonal_shift(zonalShiftId=shift_id)
    except arc.exceptions.ConflictException:
        pass
    except arc.exceptions.ResourceNotFoundException:
        pass


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB spanning 2 AZs and wait for ARC to auto-register it as a
    managed resource. Returns (load_balancer_arn, away_from_az_id)."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    arc = ctx.client("arc-zonal-shift")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an ARC managed load balancer")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span at least 2 Availability Zones in this region")
    subnet_ids = [by_az[az] for az in sorted(by_az)[:2]]

    name = ctx.unique_name("sim2realarczs")[:32].strip("-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        IpAddressType="ipv4",
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    elbv2.get_waiter("load_balancer_available").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "zonal_shift.config.enabled", "Value": "true"}],
    )

    deadline = time.monotonic() + 900.0
    resource = None
    while time.monotonic() < deadline:
        try:
            resource = arc.get_managed_resource(resourceIdentifier=lb_arn)
            if resource.get("appliedWeights"):
                break
        except (arc.exceptions.ResourceNotFoundException, arc.exceptions.AccessDeniedException):
            pass
        time.sleep(15)
    if not resource or not resource.get("appliedWeights"):
        raise AssertionError(
            f"load balancer {lb_arn} was never registered as an ARC managed resource "
            "within 15 minutes"
        )
    away_from = sorted(resource["appliedWeights"])[0]
    return lb_arn, away_from


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
