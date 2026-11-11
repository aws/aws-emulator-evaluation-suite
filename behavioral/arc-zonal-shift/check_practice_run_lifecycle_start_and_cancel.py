"""practice-run-lifecycle-start-and-cancel."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "practice-run-lifecycle-start-and-cancel"
GROUP = "state"
SERVICES = ["arc-zonal-shift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartPracticeRun creates an ACTIVE PRACTICE_RUN shift that sets the target zone's weight to 0.0;
    CancelPracticeRun ends it CANCELED with outcome INTERRUPTED and restores the weight."""
    arc = ctx.client("arc-zonal-shift")
    lb_arn, away_from = _create_nlb_managed_resource(ctx)
    _, outcome_alarm_arn = _create_ok_alarm(ctx)
    _create_practice_run_config(ctx, lb_arn, outcome_alarm_arn)

    shift = arc.start_practice_run(
        resourceIdentifier=lb_arn, awayFrom=away_from, comment="sim2real-practice-run"
    )
    shift_id = shift["zonalShiftId"]
    assert shift["status"] == "ACTIVE", f"expected StartPracticeRun status ACTIVE, got {shift['status']!r}"
    assert shift["awayFrom"] == away_from, (
        f"expected StartPracticeRun awayFrom {away_from!r}, got {shift['awayFrom']!r}"
    )

    resource = _poll_until(
        lambda: arc.get_managed_resource(resourceIdentifier=lb_arn),
        lambda r: r["appliedWeights"].get(away_from) == 0.0,
        timeout_s=180.0,
        interval_s=5.0,
    )
    matched = next(z for z in resource["zonalShifts"] if z["zonalShiftId"] == shift_id)
    assert matched["shiftType"] == "PRACTICE_RUN", (
        f"expected zonalShift {shift_id} shiftType PRACTICE_RUN, got {matched['shiftType']!r}"
    )

    canceled = arc.cancel_practice_run(zonalShiftId=shift_id)
    assert canceled["status"] == "CANCELED", (
        f"expected CancelPracticeRun status CANCELED, got {canceled['status']!r}"
    )

    resource_after_cancel = _poll_until(
        lambda: arc.get_managed_resource(resourceIdentifier=lb_arn),
        lambda r: r["appliedWeights"].get(away_from) == 1.0,
        timeout_s=120.0,
        interval_s=5.0,
    )
    weights_after = resource_after_cancel["appliedWeights"]
    assert weights_after[away_from] == 1.0, (
        f"expected appliedWeights[{away_from!r}] restored to 1.0 after cancel, got {weights_after[away_from]!r}"
    )
    still_listed = [
        z["zonalShiftId"] for z in resource_after_cancel["zonalShifts"] if z["zonalShiftId"] == shift_id
    ]
    assert not still_listed, (
        f"expected canceled practice run {shift_id} to no longer appear in the managed "
        f"resource's active zonalShifts, but it is still listed: {still_listed!r}"
    )


#: Seconds the check's teardowns may spend retrying a refusal.
_CLEANUP_BUDGET_S = 900.0


def _teardown(fn, gone_codes, retry_codes) -> None:
    """Run one teardown call: return on success or a gone code, retry retry_codes every 2 s to
    the cleanup budget, and raise anything else."""
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in retry_codes or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_ok_alarm(ctx):
    """A metric alarm with no real datapoints and TreatMissingData=notBreaching settles to
    OK once its first evaluation period elapses -- ARC's StartPracticeRun requires every
    outcome alarm to be OK, not just non-ALARM, so INSUFFICIENT_DATA is rejected too."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-arczs-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=99.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    alarm = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0],
        lambda a: a["StateValue"] == "OK",
        timeout_s=150.0,
        interval_s=10.0,
    )
    return name, alarm["AlarmArn"]


def _create_practice_run_config(ctx, resource_arn, outcome_alarm_arn, blocking_alarm_arn=None):
    arc = ctx.client("arc-zonal-shift")
    outcome_alarms = [{"type": "CLOUDWATCH", "alarmIdentifier": outcome_alarm_arn}]
    kwargs = {"resourceIdentifier": resource_arn, "outcomeAlarms": outcome_alarms}
    if blocking_alarm_arn:
        kwargs["blockingAlarms"] = [{"type": "CLOUDWATCH", "alarmIdentifier": blocking_alarm_arn}]
    arc.create_practice_run_configuration(**kwargs)

    def _cleanup():
        # A practice run still ending answers ConflictException until it is over.
        _teardown(
            lambda: arc.update_zonal_autoshift_configuration(
                resourceIdentifier=resource_arn, zonalAutoshiftStatus="DISABLED"
            ),
            ("ResourceNotFoundException",),
            ("ConflictException",),
        )
        _teardown(
            lambda: arc.delete_practice_run_configuration(resourceIdentifier=resource_arn),
            ("ResourceNotFoundException",),
            ("ConflictException",),
        )

    ctx.on_cleanup(_cleanup)


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB spanning 2 AZs, opt it in to ARC zonal shift via its own
    load balancer attribute, and wait for ARC to register it as a managed resource. Returns
    (load_balancer_arn, away_from_az_id)."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    arc = ctx.client("arc-zonal-shift")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("the check's network has no VPC to provision an ARC managed load balancer in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("the check's network does not span at least 2 Availability Zones")
    subnet_ids = [by_az[az] for az in sorted(by_az)[:2]]

    name = ctx.unique_name("sim2realarczs")[:32].strip("-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        IpAddressType="ipv4",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn),
            ("LoadBalancerNotFoundException",),
            ("ResourceInUseException",),
        )
    )
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
        time.sleep(2)
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
