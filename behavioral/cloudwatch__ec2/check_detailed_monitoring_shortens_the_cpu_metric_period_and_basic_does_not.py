"""detailed-monitoring-shortens-the-cpu-metric-period-and-basic-does-not."""

# What the check relies on:
#   - Basic monitoring publishes instance metrics OTHER than status checks in 5-minute periods;
#     detailed monitoring publishes them in 1-minute periods (manage-detailed-monitoring.html:
#     "Basic monitoring | Status check metrics are available in 1-minute periods. All other
#     metrics are available in 5-minute periods." / "Detailed monitoring | You can get metrics in
#     1-minute periods"). CPUUtilization is one of the "all other metrics".
#   - The 5-minute buckets land ON 5-minute wall-clock boundaries (epoch second % 300 == 0), so a
#     datapoint whose minute is NOT a multiple of 5 is proof of 1-minute publication.
#   - MonitorInstances takes effect within ~2 publication intervals. _DETAILED_BUDGET_S = 420 is
#     7 one-minute intervals.
#   - The first basic datapoint appears within _MONITORING_BUDGET_S = 600 of the instance reaching
#     `running`.
#   - Unit is "Percent" and the published dimension set is exactly {InstanceId}.
#   - A t3.micro from the SSM public AL2023 AMI parameter launches into the run's network and
#     reaches `running`. No AMI id and no account id is hardcoded anywhere.
#   - Wall clock ~1000-1400s: ~90s launch + up to 600s for the first basic datapoints + ~420s of
#     1-minute accumulation after the switch.
#   - Teardown is a single TerminateInstances that returns while the instances are
#     `shutting-down`; no VPC is created.
#   - The UnmonitorInstances restore leg is out of scope: proving the period returns to 5 minutes
#     needs a further ~15 minutes of accumulation.

from __future__ import annotations

from botocore.exceptions import ClientError

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "detailed-monitoring-shortens-the-cpu-metric-period-and-basic-does-not"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"

_RUNNING_BUDGET_S = 300.0
_MONITORING_BUDGET_S = 600.0
_DETAILED_BUDGET_S = 420.0
_LIST_METRICS_BUDGET_S = 180.0
#: The comparison span, in seconds, over which the two instances' publication cadence is compared.
#: 300s is exactly one basic-monitoring period, so a correct basic instance contributes 1 datapoint
#: and a correct detailed instance contributes 5.
_COMPARISON_SPAN_S = 300


# timing:real-time — metric: 300 s https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html
@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """MonitorInstances changes AWS/EC2 CPUUtilization publication for that instance from 5-minute to
    1-minute periods while a twin left on basic monitoring keeps 5-minute periods in the same window:
    cadence is decided at ingest, so neither a fixed cadence nor re-bucketing on read can fake it."""
    ec2 = ctx.client("ec2")
    cw = ctx.client("cloudwatch")

    ami_id = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami_id.startswith("ami-"), (
        f"the SSM public parameter {_AL2023_AMI_PARAM} resolved to {ami_id!r}, which is not an AMI "
        f"id; no AMI is hardcoded in this check so there is nothing to fall back to"
    )
    subnet_id = _first_default_subnet(ctx, ec2)

    # Both instances launched by ONE RunInstances call, so they are the same age to the second and
    # both start on BASIC monitoring.
    reservation = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=_INSTANCE_TYPE,
        MinCount=2,
        MaxCount=2,
        SubnetId=subnet_id,
        # Monitoring deliberately omitted: the API default is basic, and the switch below is what
        # this check is about.
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "sim2real", "Value": "cloudwatch__ec2"},
                    {"Key": "sim2real-check", "Value": CHECK},
                ],
            }
        ],
    )
    instance_ids = [i["InstanceId"] for i in reservation["Instances"]]
    assert len(instance_ids) == 2, (
        f"RunInstances returned {len(instance_ids)} instances {instance_ids!r}, expected 2 — the "
        f"twin comparison below needs both"
    )
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))
    detailed_id, basic_id = instance_ids

    for iid in instance_ids:
        state = _poll_until(
            lambda i=iid: _instance_state(ec2, i),
            lambda s: s == "running",
            timeout_s=_RUNNING_BUDGET_S,
            interval_s=10.0,
            description=f"instance {iid} reaching `running`",
            terminal_bad={"terminated", "shutting-down"},
        )
        assert state == "running", f"instance {iid} settled at state {state!r}, expected 'running'"

    # Both report basic monitoring at the API, before anything is measured at CloudWatch.
    for iid in instance_ids:
        got = _monitoring_state(ec2, iid)
        assert got == "disabled", (
            f"instance {iid} reports Monitoring.State={got!r} at launch, expected 'disabled' — both "
            f"twins must start on basic monitoring or the comparison has no baseline"
        )

    # ---- baseline: BOTH publish, and both at the 5-minute cadence ------------------------------ #
    # The positive control for the whole check: if neither instance ever publishes, everything below
    # would be vacuous. This raises rather than returning if no datapoint arrives.
    _poll_until(
        lambda: (
            len(_cpu_datapoints(cw, detailed_id, minutes=30)) >= 1
            and len(_cpu_datapoints(cw, basic_id, minutes=30)) >= 1
        ),
        lambda ok: ok,
        timeout_s=_MONITORING_BUDGET_S,
        interval_s=30.0,
        description=(
            "both basic-monitoring instances publishing at least one AWS/EC2 CPUUtilization "
            "datapoint, which is the positive control for the cadence comparison"
        ),
    )
    for iid in instance_ids:
        dps = _cpu_datapoints(cw, iid, minutes=30)
        off_grid = [
            d for d in dps if int(d["Timestamp"].timestamp()) % 300 != 0
        ]
        assert not off_grid, (
            f"instance {iid} is on BASIC monitoring but published CPUUtilization datapoints at "
            f"{[d['Timestamp'].isoformat() for d in off_grid]!r}, which are not on 5-minute "
            f"boundaries. Basic monitoring buckets all non-status-check metrics into 5-minute "
            f"periods, so an off-grid bucket means the cadence is not being honoured"
        )
        units = {d.get("Unit") for d in dps}
        assert units == {"Percent"}, (
            f"AWS/EC2 CPUUtilization datapoints for {iid} carry Unit(s) {units!r}, expected exactly "
            f"{{'Percent'}} — a utilisation reported as Count or None is invisible to any assertion "
            f"on the value alone"
        )

    # ListMetrics is its own eventually-consistent catalog, populated on a different schedule than
    # the datapoints GetMetricStatistics already served above — so a snapshot read can find the data
    # available but the catalog entry not yet indexed. Poll rather than assume synchrony.
    sets = _poll_until(
        lambda: _dimension_sets(cw, "AWS/EC2", "InstanceId", detailed_id),
        lambda s: ("InstanceId",) in s,
        timeout_s=_LIST_METRICS_BUDGET_S,
        interval_s=15.0,
        description=(
            f"ListMetrics indexing the per-instance ('InstanceId',) AWS/EC2 series for "
            f"InstanceId={detailed_id}, which GetMetricStatistics already shows is publishing"
        ),
    )
    assert ("InstanceId",) in sets, (
        f"ListMetrics reports dimension sets {sorted(sets)!r} for the AWS/EC2 series naming "
        f"InstanceId={detailed_id}; the per-instance ('InstanceId',) series must exist, because it "
        f"is the only series a per-instance alarm can be built on"
    )

    # ---- the switch: exactly one of the two twins goes to detailed monitoring ------------------ #
    resp = ec2.monitor_instances(InstanceIds=[detailed_id])
    reported = {m["InstanceId"]: m["Monitoring"]["State"] for m in resp["InstanceMonitorings"]}
    assert reported.get(detailed_id) in {"pending", "enabled"}, (
        f"MonitorInstances reported {reported!r} for {detailed_id}, expected 'pending' or 'enabled'"
    )
    switched_at = datetime.now(timezone.utc)
    assert _monitoring_state(ec2, basic_id) == "disabled", (
        f"the twin {basic_id} reports Monitoring.State="
        f"{_monitoring_state(ec2, basic_id)!r} after MonitorInstances was called on {detailed_id} "
        f"only; the switch must be per-instance or the comparison is meaningless"
    )
    _poll_until(
        lambda: _monitoring_state(ec2, detailed_id),
        lambda s: s == "enabled",
        timeout_s=120.0,
        interval_s=5.0,
        description=f"instance {detailed_id} reporting Monitoring.State='enabled'",
    )

    # ---- the discriminating observation: an OFF-GRID bucket after the switch ------------------- #
    def _off_grid_after_switch() -> list[dict]:
        return [
            d
            for d in _cpu_datapoints(cw, detailed_id, minutes=30)
            if d["Timestamp"] > switched_at and int(d["Timestamp"].timestamp()) % 300 != 0
        ]

    _poll_until(
        _off_grid_after_switch,
        lambda dps: len(dps) >= 1,
        timeout_s=_DETAILED_BUDGET_S,
        interval_s=30.0,
        description=(
            f"instance {detailed_id} publishing a CPUUtilization datapoint on a minute that is NOT "
            f"a 5-minute boundary after MonitorInstances — the single observation that separates "
            f"1-minute from 5-minute publication"
        ),
    )

    # ---- top up the wait to a fixed, deterministic point --------------------------------------- #
    # The off-grid poll above can succeed in far less than _COMPARISON_SPAN_S of wall clock — a fast
    # switch is itself evidence that MonitorInstances took effect, not a defect — so the span below cannot assume the poll
    # consumed enough time on its own.
    _poll_until(
        lambda: (datetime.now(timezone.utc) - switched_at).total_seconds(),
        lambda elapsed: elapsed >= _COMPARISON_SPAN_S,
        timeout_s=_COMPARISON_SPAN_S + 30.0,
        interval_s=5.0,
        description=(
            f"{_COMPARISON_SPAN_S}s of wall clock elapsing since the monitoring switch at "
            f"{switched_at.isoformat()}, so the comparison span below can start at or after it"
        ),
    )

    # ---- the cadence comparison, over one identical span for both twins ------------------------ #
    # A window that begins after the switch has taken effect, aligned so both twins are read over
    # exactly the same seconds.
    span_end = datetime.now(timezone.utc)
    span_start = span_end - timedelta(seconds=_COMPARISON_SPAN_S)
    assert span_start > switched_at, (
        f"the comparison span {span_start.isoformat()}..{span_end.isoformat()} starts before the "
        f"monitoring switch at {switched_at.isoformat()}; the poll above should have consumed at "
        f"least {_COMPARISON_SPAN_S}s of wall clock first"
    )

    detailed_in_span = _cpu_in_span(cw, detailed_id, span_start, span_end)
    basic_in_span = _cpu_in_span(cw, basic_id, span_start, span_end)

    assert len(detailed_in_span) >= 3, (
        f"over the {_COMPARISON_SPAN_S}s span {span_start.isoformat()}..{span_end.isoformat()} the "
        f"detailed-monitoring instance {detailed_id} published {len(detailed_in_span)} "
        f"CPUUtilization datapoints at "
        f"{[d['Timestamp'].isoformat() for d in detailed_in_span]!r}; 1-minute publication over one "
        f"5-minute span must yield at least 3 (allowing for the span's ragged ends)"
    )
    assert len(basic_in_span) <= 1, (
        f"over the SAME span the basic-monitoring twin {basic_id} published "
        f"{len(basic_in_span)} CPUUtilization datapoints at "
        f"{[d['Timestamp'].isoformat() for d in basic_in_span]!r}; a {_COMPARISON_SPAN_S}s window is "
        f"exactly one basic period, so more than one datapoint means the 5-minute cadence is not "
        f"being honoured — this is the leg a target that re-buckets on the READ period fails"
    )
    assert len(detailed_in_span) > len(basic_in_span), (
        f"the detailed instance published {len(detailed_in_span)} datapoints and its basic twin "
        f"{len(basic_in_span)} over the same {_COMPARISON_SPAN_S}s span; MonitorInstances must make "
        f"the difference observable, and equal counts mean the flag changed nothing"
    )

    # ---- positive control, after the comparison ------------------------------------------------ #
    # The twin is still alive and still publishing, so its low count is a cadence and not a death.
    twin_all = _cpu_datapoints(cw, basic_id, minutes=30)
    assert twin_all, (
        f"the basic twin {basic_id} has no CPUUtilization datapoints at all over the last 30 "
        f"minutes; its low in-span count above is then an absence, not a 5-minute cadence"
    )
    assert _monitoring_state(ec2, basic_id) == "disabled", (
        f"the basic twin {basic_id} ended the run reporting Monitoring.State="
        f"{_monitoring_state(ec2, basic_id)!r}, expected 'disabled' throughout"
    )


# ===== helpers =====
def _first_default_subnet(ctx, ec2) -> str:
    """A subnet in the run's shared network. No VPC is created, so no ENI-drain teardown is needed."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, (
        f"no shared network VPC exists in {ctx.region}; this check launches into the run's shared network rather "
        f"than creating one, so an absent shared network VPC is a prerequisite failure"
    )
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    assert subnets, f"the shared network {vpcs[0]['VpcId']} in {ctx.region} has no subnets"
    return sorted(s["SubnetId"] for s in subnets)[0]


def _monitoring_state(ec2, instance_id: str) -> str:
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0][
        "Monitoring"
    ]["State"]


def _cpu_datapoints(cw, instance_id: str, *, minutes: int) -> list[dict]:
    """CPUUtilization read at Period=60, sorted by timestamp.

    Read at the FINEST period deliberately: a Period=60 read is what exposes whether the stored
    series is 1-minute or 5-minute, because CloudWatch cannot invent buckets that were never stored.
    """
    now = datetime.now(timezone.utc)
    dps = cw.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=now - timedelta(minutes=minutes),
        EndTime=now + timedelta(minutes=1),
        Period=60,
        Statistics=["Average", "SampleCount"],
    )["Datapoints"]
    return sorted(dps, key=lambda d: d["Timestamp"])


def _cpu_in_span(cw, instance_id: str, start: datetime, end: datetime) -> list[dict]:
    dps = cw.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=start,
        EndTime=end,
        Period=60,
        Statistics=["Average", "SampleCount"],
    )["Datapoints"]
    return sorted(dps, key=lambda d: d["Timestamp"])


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _instance_state(ec2, instance_id: str):
    """The instance's state name, or None while EC2 does not yet admit the id exists.

    DescribeInstances is EVENTUALLY CONSISTENT for an id RunInstances only just returned: it can
    answer InvalidInstanceID.NotFound for a short window afterwards. Raising through the poll made
    that window fatal -- the lambda threw, the poll never got a second attempt, and the check failed
    on a launch that was in fact fine.

    Returning None instead lets the caller's own deadline decide, which is the right bound: absence
    is tolerated only for as long as the poll allows, never slept through. Every other error still
    propagates, so a genuinely wrong id or a denied call is not silently retried into a timeout.
    """
    try:
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
            return None
        raise
    for reservation in reservations:
        for inst in reservation["Instances"]:
            return inst["State"]["Name"]
    return None


def _poll_until(
    probe, predicate, *, timeout_s, interval_s, description, terminal_bad=frozenset()
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if isinstance(last, str) and last in terminal_bad:
            raise AssertionError(
                f"{description}: reached the terminal failure value {last!r}, which the poll's "
                f"target set excludes"
            )
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
