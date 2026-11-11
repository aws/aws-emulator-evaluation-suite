"""subscription-filter-delivery-failure-counts-a-deliveryerrors-datapoint."""
from __future__ import annotations

import gzip
import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "subscription-filter-delivery-failure-counts-a-deliveryerrors-datapoint"
GROUP = "telemetry"
SERVICES = ["logs"]

_MATCH_TOKEN = "SIM2REALMATCH"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Monitoring-CloudWatch-Metrics.html
@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A deleted Kinesis destination makes CloudWatch Logs publish AWS/Logs DeliveryErrors >= 1
    while the event stays stored; after the stream is recreated and the filter reissued,
    delivery resumes and the outage event is never re-delivered."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    kinesis = ctx.client("kinesis")

    group, stream = _make_group_and_stream(ctx, logs, "sim2real-behav-logs-delerr-")
    dest_name = ctx.unique_name("sim2real-behav-logs-delerr-dest-")
    original_arn = _create_kinesis_stream(ctx, kinesis, dest_name, register_cleanup=True)
    role_arn = _make_cwl_delivery_role(ctx, original_arn)

    filter_name = ctx.unique_name("sim2real-behav-delerr-filter-")
    _put_subscription_filter(ctx, logs, group, filter_name, _MATCH_TOKEN, original_arn, role_arn)

    marker = ctx.unique_name("delerr-")
    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    drainer = _ShardDrainer(kinesis, _trim_horizon_iterator(kinesis, dest_name), marker)

    before_msg = f"{_MATCH_TOKEN} {marker} before-outage"
    during_msg = f"{_MATCH_TOKEN} {marker} during-outage"
    after_msg = f"{_MATCH_TOKEN} {marker} after-restore"

    # --- Beat 1: positive control. The wiring delivers.
    written_at = time.monotonic()
    _write(logs, group, stream, [before_msg])
    _poll_until(
        drainer,
        lambda msgs: before_msg in msgs,
        timeout_s=420.0,
        interval_s=10.0,
        description=(
            f"positive control: {before_msg!r} is delivered to Kinesis stream {dest_name} "
            f"through subscription filter {filter_name}"
        ),
    )
    latency_s = time.monotonic() - written_at

    # Discover the dimension triple while the filter is demonstrably delivering. The
    # DestinationType value is undocumented, so it is read off the target; DeliveryErrors is
    # published under the same triple.
    published = _poll_until(
        lambda: _discover(cw, "ForwardedLogEvents", group),
        lambda m: m is not None,
        timeout_s=600.0,
        interval_s=20.0,
        description=(
            f"AWS/Logs ForwardedLogEvents for {group} becomes discoverable so the "
            f"DestinationType dimension value can be read off the target"
        ),
    )
    dimensions = published["Dimensions"]
    dim_map = {d["Name"]: d["Value"] for d in dimensions}
    assert dim_map["FilterName"] == filter_name, (
        f"expected the discovered FilterName dimension to be {filter_name!r}, got "
        f"{dim_map.get('FilterName')!r}"
    )

    # --- Beat 2: break exactly one thing -- the destination. Absence in beat 3 is then
    # STRUCTURAL, not a matter of waiting: the stream does not exist to receive anything.
    kinesis.delete_stream(StreamName=dest_name, EnforceConsumerDeletion=True)
    _poll_until(
        lambda: _stream_missing(kinesis, dest_name),
        lambda gone: gone,
        timeout_s=300.0,
        interval_s=5.0,
        description=f"Kinesis stream {dest_name} is fully deleted (DescribeStream not found)",
    )

    # --- Beat 3: the SPECIFIC failure signal, and the event is not lost.
    _write(logs, group, stream, [during_msg])
    errors = _poll_until(
        lambda: _stats(cw, "AWS/Logs", "DeliveryErrors", dimensions, window_start),
        lambda dps: bool(dps) and sum(d["Sum"] for d in dps) >= 1.0,
        timeout_s=600.0,
        interval_s=20.0,
        description=(
            f"AWS/Logs DeliveryErrors for {filter_name} reaches Sum >= 1 while its "
            f"destination is deleted -- a target that silently drops the delivery publishes "
            f"nothing here and is indistinguishable from a target with no delivery path"
        ),
    )
    err_sum = sum(dp["Sum"] for dp in errors)
    assert err_sum >= 1.0, (
        f"expected AWS/Logs DeliveryErrors Sum >= 1 for {filter_name} after the destination "
        f"was deleted, got {err_sum}"
    )
    err_units = {dp["Unit"] for dp in errors}
    assert err_units == {"None"}, (
        f"expected DeliveryErrors datapoints to carry Unit 'None' per the AWS/Logs metric "
        f"table, got {sorted(err_units)}"
    )
    stored = _poll_until(
        lambda: _stored_messages(logs, group, marker),
        lambda msgs: during_msg in msgs,
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"the event written during the outage is still stored in {group} -- a delivery "
            f"failure must not lose the log event"
        ),
    )
    assert before_msg in stored and during_msg in stored, (
        f"expected both {before_msg!r} and {during_msg!r} readable from {group}, got {stored!r}"
    )

    # --- Beat 4: restore. A Kinesis stream recreated under the same name must present the
    # identical ARN, so the filter's stored destinationArn resolves again untouched.
    restored_arn = _create_kinesis_stream(ctx, kinesis, dest_name, register_cleanup=False)
    assert restored_arn == original_arn, (
        f"expected the recreated stream to present the identical ARN {original_arn!r} "
        f"(account, region and name determine it), got {restored_arn!r}; the restore beat "
        f"only tests the same wiring if the ARN is unchanged"
    )

    # --- Beat 4.5: recreating the stream under the identical ARN does NOT by itself revive
    # delivery, even after 1200s of waiting. CloudWatch Logs marks the
    # filter's destination unhealthy on the non-retryable failure and only re-validates it on
    # the NEXT PutSubscriptionFilter call, which is why this reissues the identical
    # configuration rather than only fixing the resource underneath it.
    _reput_subscription_filter(logs, group, filter_name, _MATCH_TOKEN, restored_arn, role_arn)

    # --- Beat 5: the identical call now succeeds, at the consumer.
    restored_drainer = _ShardDrainer(
        kinesis, _trim_horizon_iterator(kinesis, dest_name), marker
    )
    _write(logs, group, stream, [after_msg])
    delivered = _poll_until(
        restored_drainer,
        lambda msgs: after_msg in msgs,
        timeout_s=420.0,
        interval_s=10.0,
        description=(
            f"after the destination is restored and the subscription filter reissued, the "
            f"identical write delivers {after_msg!r} again (positive latency before the "
            f"outage was {latency_s:.0f}s)"
        ),
    )
    assert during_msg not in delivered, (
        f"expected {during_msg!r} to be dropped permanently: ResourceNotFoundException is "
        f"documented as NON-retryable, so CloudWatch Logs must not re-deliver it once the "
        f"destination returns; delivered set was {delivered!r}"
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_group_and_stream(ctx, logs, prefix: str) -> tuple[str, str]:
    group = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = f"{group}-stream"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    return group, stream


def _create_kinesis_stream(ctx, kinesis, name: str, *, register_cleanup: bool) -> str:
    kinesis.create_stream(StreamName=name, ShardCount=1)
    if register_cleanup:

        def _cleanup() -> None:
            # The check deletes and recreates this stream mid-body. Only the specific
            # not-found error is tolerated, so a genuine cleanup failure still surfaces.
            try:
                kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
            except kinesis.exceptions.ResourceNotFoundException:
                return

        ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=name)["StreamDescription"]["StreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"Kinesis stream {name} becomes ACTIVE",
    )
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    return kinesis.describe_stream(StreamName=name)["StreamDescription"]["StreamARN"]


def _stream_missing(kinesis, name: str) -> bool:
    try:
        kinesis.describe_stream(StreamName=name)
    except kinesis.exceptions.ResourceNotFoundException:
        return True
    return False


def _make_cwl_delivery_role(ctx, dest_arn: str) -> str:
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-logs-delerr-role-")
    policy_name = "cwl-to-destination"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "sts:AssumeRole",
                # AWS's own confused-deputy example scopes this to the account/region, not
                # a specific log group (docs.aws.amazon.com/AmazonCloudWatch/latest/logs/
                # SubscriptionFilters.html): "arn:aws:logs:{region}:{account}:*". A
                # log-group-scoped SourceArn never matches the trust condition, so AssumeRole
                # silently fails and every
                # PutSubscriptionFilter call reads as "Could not deliver test message" for
                # the full retry window, indistinguishable from IAM propagation lag.
                "Condition": {
                    "StringLike": {"aws:SourceArn": f"arn:aws:logs:{ctx.region}:{account}:*"}
                },
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
                        # The stream is deleted and recreated under the same name, so the
                        # ARN is stable and the policy needs no repair mid-check.
                        "Resource": dest_arn,
                    }
                ],
            }
        ),
    )
    return role_arn


def _reput_subscription_filter(logs, group, filter_name, pattern, dest_arn, role_arn) -> None:
    """Reissue an already-registered filter's configuration unchanged. No new cleanup is
    registered -- the original PutSubscriptionFilter call already owns that."""

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
        _attempt,
        lambda r: r is True,
        timeout_s=180.0,
        interval_s=10.0,
        description=f"PutSubscriptionFilter re-accepts role {role_arn} for {group}",
    )


def _put_subscription_filter(ctx, logs, group, filter_name, pattern, dest_arn, role_arn) -> None:
    _reput_subscription_filter(logs, group, filter_name, pattern, dest_arn, role_arn)
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=filter_name)
    )


def _write(logs, group: str, stream: str, messages: list[str]) -> None:
    base = _now_ms()
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(messages)],
    )
    rejected = resp.get("rejectedLogEventsInfo")
    assert not rejected, (
        f"expected {len(messages)} in-window events accepted for {group}, got "
        f"rejectedLogEventsInfo {rejected!r}"
    )


def _trim_horizon_iterator(kinesis, stream_name: str) -> str:
    # DescribeStream can report ACTIVE with the shard listed while
    # GetShardIterator for that same shard still answers ResourceNotFoundException for a
    # short window afterward -- most visibly for a stream recreated under a name just deleted
    # (the restore beat). A bounded retry absorbs that propagation gap; it re-raises past the
    # deadline, so it never masks a genuinely missing stream.
    shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][
        0
    ]["ShardId"]
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return kinesis.get_shard_iterator(
                StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
            )["ShardIterator"]
        except kinesis.exceptions.ResourceNotFoundException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


class _ShardDrainer:
    """Accumulate delivered messages carrying ``marker`` across polls; the shard iterator
    advances with each GetRecords call and is carried forward, never restarted."""

    def __init__(self, kinesis, iterator: str, marker: str) -> None:
        self._kinesis = kinesis
        self._iterator = iterator
        self._marker = marker
        self.messages: list[str] = []

    def __call__(self) -> list[str]:
        resp = self._kinesis.get_records(ShardIterator=self._iterator, Limit=500)
        self._iterator = resp["NextShardIterator"]
        for record in resp["Records"]:
            payload = json.loads(gzip.decompress(record["Data"]))
            for event in payload["logEvents"]:
                if self._marker in event["message"]:
                    self.messages.append(event["message"])
        return list(self.messages)


def _discover(cw, metric_name: str, log_group: str):
    resp = cw.list_metrics(
        Namespace="AWS/Logs",
        MetricName=metric_name,
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


def _stored_messages(logs, group: str, marker: str) -> list[str]:
    resp = logs.filter_log_events(logGroupName=group, filterPattern=f'"{marker}"', limit=50)
    return sorted(e["message"] for e in resp["events"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
