"""cloudwatch-alarm-breach-fails-the-global-endpoint-over-to-secondary."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, EndpointConnectionError

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-breach-fails-the-global-endpoint-over-to-secondary"
GROUP = "global-endpoints"
SERVICES = ["cloudwatch", "events", "route53", "sqs"]

#: A freshly created endpoint's own DNS name is not resolvable right away; AWS documents an RTO
#: of up to 420 s for a global endpoint to start serving, and plain post-create DNS propagation
#: is the same order of magnitude.
_DNS_PROPAGATION_TIMEOUT_S = 900.0
#: Publishing a breaching datapoint, then waiting for the Route 53 health check to notice and
#: the endpoint to fail over, is the same documented RTO.
_FAILOVER_TIMEOUT_S = 900.0
_ACTIVE_TIMEOUT_S = 180.0
_DELIVERY_TIMEOUT_S = 90.0
#: How long the primary's queue is drained after the control, catching an out-of-order late copy.
_QUIET_WINDOW_S = 30.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _expired(ctx, description, timeout_s, detail):
    """The error for a capped wait that ran out: TimeoutError when the run budget ended it."""
    if _budget_spent(ctx):
        return TimeoutError(f"{description}: the run budget ended first; not graded")
    return AssertionError(f"{description} not met within {timeout_s:.0f}s; {detail}")


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A breaching datapoint on the CloudWatch alarm behind the endpoint's Route 53 health
    check fails the global endpoint over: the same PutEvents call that reached the primary
    bus's rule target now reaches only the secondary's, and not the primary.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-global-endpoints.html
    """
    events = ctx.client("events")
    home = ctx.region
    away = "us-west-2" if home != "us-west-2" else "us-east-1"

    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real/gefo")
    metric_name = ctx.unique_name("latency-")
    threshold = 1.0
    alarm_name = ctx.unique_name("sim2real-behav-gefoalarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name, Namespace=namespace, MetricName=metric_name,
        Statistic="Average", Period=60, EvaluationPeriods=1, Threshold=threshold,
        ComparisonOperator="GreaterThanThreshold", TreatMissingData="missing",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))
    alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly the created alarm, got {alarms!r}"
    partition = alarms[0]["AlarmArn"].split(":")[1]

    health_check_arn = _create_cloudwatch_metric_health_check(ctx, alarm_name, partition)
    primary_bus_arn = f"arn:{partition}:events:{home}:{ctx.account}:event-bus/default"
    secondary_bus_arn = f"arn:{partition}:events:{away}:{ctx.account}:event-bus/default"

    name = ctx.unique_name("sim2real-behav-gefo-")
    events.create_endpoint(
        Name=name,
        RoutingConfig={"FailoverConfig": {
            "Primary": {"HealthCheck": health_check_arn},
            "Secondary": {"Route": away},
        }},
        EventBuses=[{"EventBusArn": primary_bus_arn}, {"EventBusArn": secondary_bus_arn}],
        ReplicationConfig={"State": "DISABLED"},
    )
    ctx.on_cleanup(_teardown(lambda: events.delete_endpoint(Name=name), "ResourceNotFoundException"))

    final = _poll_until(ctx, lambda: events.describe_endpoint(Name=name),
                        lambda r: r.get("State") == "ACTIVE", cap_s=_ACTIVE_TIMEOUT_S,
                        description=f"endpoint {name} ACTIVE")
    endpoint_id = final["EndpointId"]

    source = ctx.unique_name("sim2real.gefailover.")
    detail_type = "sim2real-global-endpoint-failover"
    home_queue_url, home_queue_arn = _create_queue(ctx, home)
    _put_rule_with_target(ctx, events, home, source, home_queue_url, home_queue_arn)
    events_away = ctx.client("events", region=away)
    away_queue_url, away_queue_arn = _create_queue(ctx, away)
    _put_rule_with_target(ctx, events_away, away, source, away_queue_url, away_queue_arn)

    def put_via_endpoint(marker: str, cap_s: float) -> None:
        resp = _put_events_with_dns_retry(ctx, events, cap_s, EndpointId=endpoint_id, Entries=[{
            "EventBusName": primary_bus_arn, "Source": source, "DetailType": detail_type,
            "Detail": json.dumps({"marker": marker}),
        }])
        assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"

    # Positive control: before any failover, PutEvents through the endpoint reaches the primary.
    before_marker = ctx.unique_name("m-before-")
    put_via_endpoint(before_marker, _DNS_PROPAGATION_TIMEOUT_S)
    _drain_until_marker(ctx, home, home_queue_url, before_marker, cap_s=_DELIVERY_TIMEOUT_S)

    cw.put_metric_data(Namespace=namespace, MetricData=[{
        "MetricName": metric_name, "Value": threshold + 1.0, "Unit": "Seconds"}])
    _poll_health_check_unhealthy(ctx, health_check_arn, cap_s=_FAILOVER_TIMEOUT_S)

    # The health check going unhealthy and the endpoint itself re-routing are two separate
    # propagation steps; re-publish with a fresh marker each round until one lands on the
    # secondary. Each round closes the client's pooled connections first, so its PutEvents
    # resolves the endpoint's DNS name afresh rather than reusing a connection to the primary.
    away_env, sent_markers = None, []
    failover_s = _budget_s(ctx, _FAILOVER_TIMEOUT_S)
    deadline = time.monotonic() + failover_s
    while away_env is None and (remaining := deadline - time.monotonic()) > 0:
        candidate = ctx.unique_name("m-after-")
        events.close()
        put_via_endpoint(candidate, remaining)
        sent_markers.append(candidate)
        # Match any marker sent so far: an earlier round's event may be the first to fail over.
        away_env = _drain_until_marker(ctx, away, away_queue_url, frozenset(sent_markers),
                                       cap_s=15.0, required=False)
    if away_env is None:
        raise _expired(ctx, "an event through the endpoint reaching the secondary bus's target",
                       failover_s, f"sent {len(sent_markers)} marker(s)")
    assert away_env["source"] == source and away_env["detail-type"] == detail_type, (
        f"failed-over delivery does not carry the original event: {away_env!r}"
    )

    # Absence at the primary, by contrast with a control ordered after it: once the final
    # endpoint event has reached the secondary, a control event put directly on the primary's
    # default bus (no EndpointId) matches the same rule; draining the primary's queue up to that
    # control must not meet the final endpoint event.
    final_marker = ctx.unique_name("m-final-")
    events.close()
    put_via_endpoint(final_marker, _DNS_PROPAGATION_TIMEOUT_S)
    _drain_until_marker(ctx, away, away_queue_url, final_marker, cap_s=_DELIVERY_TIMEOUT_S)
    control_marker = ctx.unique_name("m-control-")
    resp = events.put_events(Entries=[{
        "Source": source, "DetailType": detail_type, "Detail": json.dumps({"marker": control_marker}),
    }])
    assert resp["FailedEntryCount"] == 0, f"PutEvents to the primary bus rejected the control: {resp['Entries']!r}"
    seen = []
    _drain_until_marker(ctx, home, home_queue_url, control_marker, cap_s=_DELIVERY_TIMEOUT_S, seen=seen)
    # Standard queues do not order independent deliveries, so keep draining for a quiet window
    # after the control: a late copy of the final event would still be caught here.
    _drain_until_marker(ctx, home, home_queue_url, ctx.unique_name("m-never-"),
                        cap_s=_QUIET_WINDOW_S, required=False, seen=seen)
    assert final_marker not in seen, (
        f"after failover, the endpoint event still reached the primary bus's target: {seen!r}"
    )


def _create_cloudwatch_metric_health_check(ctx, alarm_name: str, partition: str) -> str:
    route53 = ctx.client("route53")
    resp = route53.create_health_check(
        CallerReference=ctx.unique_name("sim2real-behav-gefohc-"),
        HealthCheckConfig={
            "Type": "CLOUDWATCH_METRIC",
            "AlarmIdentifier": {"Name": alarm_name, "Region": ctx.region},
            "InsufficientDataHealthStatus": "LastKnownStatus",
        },
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(_teardown(lambda: route53.delete_health_check(HealthCheckId=hc_id), "NoSuchHealthCheck"))
    route53.change_tags_for_resource(ResourceType="healthcheck", ResourceId=hc_id,
                                     AddTags=[{"Key": "sim2real", "Value": CHECK}])
    return f"arn:{partition}:route53:::healthcheck/{hc_id}"


def _poll_health_check_unhealthy(ctx, health_check_arn: str, *, cap_s: float) -> None:
    route53 = ctx.client("route53")
    hc_id = health_check_arn.rsplit("/", 1)[-1]
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            observations = route53.get_health_check_status(HealthCheckId=hc_id)["HealthCheckObservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchHealthCheck":
                raise
            observations = []
        last = [o["StatusReport"]["Status"] for o in observations]
        if observations and all(s.startswith("Failure:") for s in last):
            return
        time.sleep(2.0)
    raise _expired(ctx, f"every checker of Route 53 health check {health_check_arn} unhealthy",
                   timeout_s, f"last observations: {last!r}")


def _create_queue(ctx, region: str) -> tuple[str, str]:
    sqs = ctx.client("sqs", region=region)
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-gefoq-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _put_rule_with_target(ctx, events, region: str, source: str, queue_url: str, queue_arn: str) -> str:
    rule_name = ctx.unique_name("sim2real-behav-geforule-")
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps({"source": [source]}),
                               State="ENABLED", Tags=[{"Key": "sim2real", "Value": CHECK}])["RuleArn"]

    def _delete_rule() -> None:
        try:
            events.remove_targets(Rule=rule_name, Ids=["sim2real-target"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_teardown(_delete_rule, "ResourceNotFoundException"))
    sqs = ctx.client("sqs", region=region)
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    resp = events.put_targets(Rule=rule_name, Targets=[{"Id": "sim2real-target", "Arn": queue_arn}])
    assert resp["FailedEntryCount"] == 0, f"PutTargets in {region} failed: {resp['FailedEntries']!r}"
    return rule_arn


def _put_events_with_dns_retry(ctx, events, cap_s: float, **kwargs) -> dict:
    """PutEvents, retried while the endpoint's DNS name does not resolve yet."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return events.put_events(**kwargs)
        except EndpointConnectionError as exc:
            if time.monotonic() >= deadline:
                raise _expired(ctx, "the endpoint's DNS name resolving for PutEvents",
                               timeout_s, f"last error: {exc}") from exc
            time.sleep(10.0)


def _drain_until_marker(ctx, region: str, queue_url: str, marker: str | frozenset[str], *,
                        cap_s: float, required: bool = True, seen: list | None = None) -> dict | None:
    """Receive and delete until an event carrying marker (or any of a set of markers) arrives;
    return its envelope.

    Every marker received on the way is appended to seen. When required is False, a wait that runs
    out returns None instead of failing.
    """
    sqs = ctx.client("sqs", region=region)
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while (remaining := deadline - time.monotonic()) > 0:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=max(1, min(5, int(remaining))))
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            got = body["detail"].get("marker") if isinstance(body.get("detail"), dict) else None
            if seen is not None:
                seen.append(got)
            if got in (marker if isinstance(marker, frozenset) else {marker}):
                return body
    if not required and not _budget_spent(ctx):
        return None
    raise _expired(ctx, f"an event carrying marker {marker!r} reaching {queue_url}", timeout_s,
                   f"markers seen: {seen!r}")


def _poll_until(ctx, probe, predicate, *, cap_s: float, description: str, interval_s: float = 2.0):
    """Poll probe() until predicate(result), under a deadline capped by the run budget."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise _expired(ctx, description, timeout_s, f"last result: {last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
