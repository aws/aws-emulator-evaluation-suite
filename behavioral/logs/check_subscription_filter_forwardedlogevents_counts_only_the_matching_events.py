"""subscription-filter-forwardedlogevents-counts-only-the-matching-events."""
from __future__ import annotations

import gzip
import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "subscription-filter-forwardedlogevents-counts-only-the-matching-events"
GROUP = "telemetry"
SERVICES = ["logs"]

_MATCH_TOKEN = "SIM2REALMATCH"
_EXPECTED_DIMENSION_NAMES = {"LogGroupName", "DestinationType", "FilterName"}


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Monitoring-CloudWatch-Metrics.html
@tags("axis:happy-path", "cap:c3", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CloudWatch Logs publishes AWS/Logs ForwardedLogEvents for a subscription filter with
    the EXACT number of events the filter pattern matched -- not the number written -- under
    the documented LogGroupName/DestinationType/FilterName dimensions."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    kinesis = ctx.client("kinesis")

    group, stream = _make_group_and_stream(ctx, logs, "sim2real-behav-logs-fwd-")
    dest_stream = _make_kinesis_stream(ctx, kinesis, "sim2real-behav-logs-fwd-dest-")
    dest_arn = kinesis.describe_stream(StreamName=dest_stream)["StreamDescription"][
        "StreamARN"
    ]
    role_arn = _make_cwl_delivery_role(ctx, group, dest_arn)

    filter_name = ctx.unique_name("sim2real-behav-fwd-filter-")
    _put_subscription_filter(ctx, logs, group, filter_name, _MATCH_TOKEN, dest_arn, role_arn)

    marker = ctx.unique_name("fwd-")
    drainer = _ShardDrainer(kinesis, _trim_horizon_iterator(kinesis, dest_stream), marker)

    matching = [f"{_MATCH_TOKEN} {marker} one", f"{_MATCH_TOKEN} {marker} two", f"{_MATCH_TOKEN} {marker} three"]
    non_matching = [f"quiet {marker} four", f"quiet {marker} five"]

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    base = _now_ms()
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base + i, "message": m}
            for i, m in enumerate(matching + non_matching)
        ],
    )
    rejected = resp.get("rejectedLogEventsInfo")
    assert not rejected, (
        f"expected all {len(matching) + len(non_matching)} in-window events accepted, got "
        f"rejectedLogEventsInfo {rejected!r}"
    )

    delivered = _poll_until(
        ctx,
        drainer,
        lambda pair: len(pair[0]) >= len(matching),
        timeout_s=420.0,
        interval_s=1.0,
        description=(
            f"all {len(matching)} matching log events arrive on Kinesis stream "
            f"{dest_stream} through subscription filter {filter_name}"
        ),
    )[0]
    assert sorted(delivered) == sorted(matching), (
        f"expected the consumer to receive exactly the {len(matching)} events matching "
        f"{_MATCH_TOKEN!r}; got {len(delivered)} messages, extra="
        f"{sorted(set(delivered) - set(matching))}, missing="
        f"{sorted(set(matching) - set(delivered))}"
    )

    # The DestinationType dimension value is not documented, so it is discovered, not guessed.
    published = _poll_until(
        ctx,
        lambda: _discover_forwarded_metric(cw, group),
        lambda m: m is not None,
        timeout_s=600.0,
        interval_s=2.0,
        description=(
            f"AWS/Logs ForwardedLogEvents for log group {group} becomes discoverable via "
            f"ListMetrics so its DestinationType value can be read off the target"
        ),
    )
    dim_names = {d["Name"] for d in published["Dimensions"]}
    assert dim_names == _EXPECTED_DIMENSION_NAMES, (
        f"expected ForwardedLogEvents for a LOG-GROUP-level subscription filter to be "
        f"published under exactly {sorted(_EXPECTED_DIMENSION_NAMES)} (PolicyLevel is "
        f"documented for ACCOUNT-level filters only), got {sorted(dim_names)}"
    )
    dim_map = {d["Name"]: d["Value"] for d in published["Dimensions"]}
    assert dim_map["FilterName"] == filter_name, (
        f"expected the FilterName dimension to name the filter this check created "
        f"({filter_name!r}), got {dim_map['FilterName']!r}"
    )

    # DescribeSubscriptionFilters reports the configuration, never how many events it forwarded.
    forwarded = _poll_until(
        ctx,
        lambda: _stats(cw, "AWS/Logs", "ForwardedLogEvents", published["Dimensions"], window_start),
        lambda dps: bool(dps) and sum(d["Sum"] for d in dps) >= float(len(matching)),
        timeout_s=420.0,
        interval_s=2.0,
        description=(
            f"AWS/Logs ForwardedLogEvents for {filter_name} reaches Sum >= {len(matching)}"
        ),
    )
    forwarded_sum = sum(dp["Sum"] for dp in forwarded)
    assert forwarded_sum == float(len(matching)), (
        f"expected ForwardedLogEvents Sum == {len(matching)} -- the filter pattern is "
        f"applied BEFORE the count, so the {len(non_matching)} non-matching events in the "
        f"same PutLogEvents batch must not be counted; got {forwarded_sum} "
        f"({float(len(matching) + len(non_matching))} would mean the pattern is ignored)"
    )
    units = {dp["Unit"] for dp in forwarded}
    assert units == {"None"}, (
        f"expected ForwardedLogEvents datapoints to carry Unit 'None' per the AWS/Logs "
        f"metric table, got {sorted(units)}"
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_group_and_stream(ctx, logs, prefix: str) -> tuple[str, str]:
    group = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = f"{group}-stream"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    return group, stream


def _make_kinesis_stream(ctx, kinesis, prefix: str) -> str:
    name = ctx.unique_name(prefix)
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    _poll_until(
        ctx,
        lambda: kinesis.describe_stream(StreamName=name)["StreamDescription"]["StreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=1.0,
        description=f"Kinesis stream {name} becomes ACTIVE before it can be a subscription target",
    )
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    return name


def _make_cwl_delivery_role(ctx, log_group: str, dest_arn: str) -> str:
    """Create the role CloudWatch Logs assumes to write to the destination.

    No SourceArn condition on the trust policy: with one, PutSubscriptionFilter's test-message
    delivery fails with InvalidParameterException even when the stream is ACTIVE.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-logs-fwd-role-")
    policy_name = "cwl-to-destination"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                        "Resource": dest_arn,
                    }
                ],
            }
        ),
    )
    return role_arn


def _put_subscription_filter(ctx, logs, group, filter_name, pattern, dest_arn, role_arn) -> None:
    """PutSubscriptionFilter validates the role by assuming it, so it is retried against
    IAM propagation -- a bounded retry with a deadline that raises, not a sleep."""

    def _attempt():
        try:
            logs.put_subscription_filter(
                logGroupName=group,
                filterName=filter_name,
                filterPattern=pattern,
                destinationArn=dest_arn,
                roleArn=role_arn,
            )
        except logs.exceptions.InvalidParameterException as exc:
            return str(exc)
        return True

    _poll_until(
        ctx,
        _attempt,
        lambda r: r is True,
        timeout_s=180.0,
        interval_s=2.0,
        description=(
            f"PutSubscriptionFilter accepts role {role_arn} for {group} once the IAM trust "
            f"policy has propagated"
        ),
    )
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=filter_name)
    )


def _trim_horizon_iterator(kinesis, stream_name: str) -> str:
    shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][
        0
    ]["ShardId"]
    return kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]


class _ShardDrainer:
    """Accumulate delivered messages carrying ``marker`` across polls. The shard iterator
    advances with each GetRecords call, so it is carried forward rather than restarted --
    restarting at TRIM_HORIZON each poll would re-count the same records."""

    def __init__(self, kinesis, iterator: str, marker: str) -> None:
        self._kinesis = kinesis
        self._iterator = iterator
        self._marker = marker
        self.messages: list[str] = []

    def __call__(self) -> tuple[list[str], int]:
        resp = self._kinesis.get_records(ShardIterator=self._iterator, Limit=500)
        self._iterator = resp["NextShardIterator"]
        for record in resp["Records"]:
            payload = json.loads(gzip.decompress(record["Data"]))
            for event in payload["logEvents"]:
                if self._marker in event["message"]:
                    self.messages.append(event["message"])
        return list(self.messages), len(self.messages)


def _discover_forwarded_metric(cw, log_group: str):
    resp = cw.list_metrics(
        Namespace="AWS/Logs",
        MetricName="ForwardedLogEvents",
        Dimensions=[{"Name": "LogGroupName", "Value": log_group}],
    )
    for metric in resp["Metrics"]:
        return metric
    return None


def _stats(cw, namespace, metric_name, dimensions, start):
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60,
        Statistics=["Sum", "SampleCount"],
    )
    return resp["Datapoints"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
