"""practice-run-blocked-by-alarm-in-alarm-state-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "practice-run-blocked-by-alarm-in-alarm-state-rejected"
GROUP = "errors"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartPracticeRun succeeds while the blocking alarm is OK, fails ConflictException and creates no
    shift while it is in ALARM, and succeeds again once the alarm is back to OK."""
    arc = ctx.client("arc-zonal-shift")
    cw = ctx.client("cloudwatch")
    lb_arn, away_from = _create_nlb_managed_resource(ctx)
    _, outcome_alarm_arn = _create_ok_alarm(ctx, "outcome")
    blocking_alarm_name, blocking_alarm_arn = _create_ok_alarm(ctx, "blocking")

    arc.create_practice_run_configuration(
        resourceIdentifier=lb_arn,
        outcomeAlarms=[{"type": "CLOUDWATCH", "alarmIdentifier": outcome_alarm_arn}],
        blockingAlarms=[{"type": "CLOUDWATCH", "alarmIdentifier": blocking_alarm_arn}],
    )
    ctx.on_cleanup(lambda: _delete_config_if_present(arc, lb_arn))

    # Positive control: with the blocking alarm OK, StartPracticeRun succeeds and the shift is
    # independently visible; cancel it to return to a clean baseline before breaking anything.
    baseline = arc.start_practice_run(
        resourceIdentifier=lb_arn, awayFrom=away_from, comment="baseline-control"
    )
    baseline_id = baseline["zonalShiftId"]
    assert baseline["status"] == "ACTIVE", f"expected ACTIVE, got {baseline!r}"
    baseline_active = _active_shift_ids(arc, lb_arn)
    assert baseline_id in baseline_active, (
        f"expected {baseline_id} visible via list_zonal_shifts, got {baseline_active}"
    )
    canceled = arc.cancel_practice_run(zonalShiftId=baseline_id)
    assert canceled["status"] == "CANCELED", f"expected CANCELED, got {canceled!r}"
    after_cancel = _active_shift_ids(arc, lb_arn)
    assert baseline_id not in after_cancel, (
        f"expected {baseline_id} no longer ACTIVE after cancel, got {after_cancel}"
    )

    # Break exactly one thing: force the blocking alarm into ALARM.
    cw.set_alarm_state(
        AlarmName=blocking_alarm_name, StateValue="ALARM", StateReason="sim2real test"
    )
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[blocking_alarm_name])["MetricAlarms"][0][
            "StateValue"
        ],
        lambda s: s == "ALARM",
        timeout_s=30.0,
        interval_s=2.0,
    )

    code, message = _error_detail(
        lambda: arc.start_practice_run(
            resourceIdentifier=lb_arn, awayFrom=away_from, comment="blocked-attempt"
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}: {message}"
    expected_message = "Cannot start practice run when blocking alarms are red"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect: no shift was created for this resource while blocked.
    blocked_active = _active_shift_ids(arc, lb_arn)
    assert blocked_active == [], f"expected no active shift while blocked, got {blocked_active}"

    # Restore, and the identical call now succeeds.
    cw.set_alarm_state(AlarmName=blocking_alarm_name, StateValue="OK", StateReason="cleared")
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[blocking_alarm_name])["MetricAlarms"][0][
            "StateValue"
        ],
        lambda s: s == "OK",
        timeout_s=30.0,
        interval_s=2.0,
    )
    started = arc.start_practice_run(
        resourceIdentifier=lb_arn, awayFrom=away_from, comment="unblocked-attempt"
    )
    shift_id = started["zonalShiftId"]
    assert started["status"] == "ACTIVE", f"expected ACTIVE, got {started!r}"
    ctx.on_cleanup(lambda: _cancel_practice_run_if_active(arc, shift_id))

    # Terminal read: independent of the mutating call, at the destination.
    final_active = _active_shift_ids(arc, lb_arn)
    assert shift_id in final_active, (
        f"expected {shift_id} visible via list_zonal_shifts after restore, got {final_active}"
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


def _error_detail(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _active_shift_ids(arc, resource_arn):
    items = arc.list_zonal_shifts(resourceIdentifier=resource_arn)["items"]
    return [i["zonalShiftId"] for i in items if i["status"] == "ACTIVE"]


def _cancel_practice_run_if_active(arc, shift_id):
    try:
        arc.cancel_practice_run(zonalShiftId=shift_id)
    except arc.exceptions.ConflictException:
        pass
    except arc.exceptions.ResourceNotFoundException:
        pass


def _delete_config_if_present(arc, resource_arn):
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


def _create_ok_alarm(ctx, suffix):
    """A metric alarm with no datapoints and TreatMissingData=notBreaching settles to OK once
    its first evaluation period elapses. StartPracticeRun refuses while any outcome alarm is
    not OK, INSUFFICIENT_DATA included, so the alarm is polled to OK before it is used."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name(f"sim2real-arczs-alarm-{suffix}-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))
    alarm = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0],
        lambda a: a["StateValue"] == "OK",
        timeout_s=150.0,
        interval_s=10.0,
    )
    return name, alarm["AlarmArn"]


def _create_nlb_managed_resource(ctx):
    """Provision an internal NLB spanning 2 AZs, opt it in to ARC zonal shift, and wait for ARC
    to register it as a managed resource. Returns (load_balancer_arn, away_from_az_id)."""
    from botocore.exceptions import ClientError

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

    name = ctx.unique_name("s2rarczs")[:32].strip("-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        IpAddressType="ipv4",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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

    # ARC does not auto-discover Network Load Balancers: a load balancer only becomes an ARC
    # managed resource once zonal-shift integration is explicitly turned on. Without this call,
    # GetManagedResource answers AccessDeniedException for the whole poll window.
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "zonal_shift.config.enabled", "Value": "true"}],
    )

    deadline = time.monotonic() + 900.0
    resource = None
    while time.monotonic() < deadline:
        try:
            candidate = arc.get_managed_resource(resourceIdentifier=lb_arn)
            if candidate.get("appliedWeights"):
                resource = candidate
                break
        except arc.exceptions.ResourceNotFoundException:
            pass
        except ClientError as e:
            # Real AWS answers AccessDeniedException, not ResourceNotFoundException, for the
            # window before ARC has discovered the load balancer as a managed resource.
            if e.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
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
