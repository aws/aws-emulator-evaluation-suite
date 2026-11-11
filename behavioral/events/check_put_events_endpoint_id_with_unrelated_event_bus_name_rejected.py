"""put-events-endpoint-id-with-unrelated-event-bus-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, EndpointConnectionError

from behavioral_harness import tags

CHECK = "put-events-endpoint-id-with-unrelated-event-bus-name-rejected"
GROUP = "global-endpoints"
SERVICES = ["events"]

#: A freshly created endpoint's own DNS name is not resolvable right away; AWS documents an RTO
#: of up to 420 s for a global endpoint to start serving, and plain post-create DNS propagation
#: is the same order of magnitude.
_DNS_PROPAGATION_TIMEOUT_S = 900.0


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents through a real global endpoint, naming an EventBusName that is neither of the
    endpoint's two configured buses, fails that one entry with InvalidArgument; the same
    endpoint still delivers normally once the call names one of its own buses.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html
    """
    events = ctx.client("events")
    queue_url, queue_arn = _create_queue(ctx)
    partition = queue_arn.split(":")[1]
    endpoint_id, primary_bus_arn = _create_endpoint(ctx, partition)

    unrelated_bus_arn = f"arn:{partition}:events:{ctx.region}:{ctx.account}:event-bus/{ctx.unique_name('sim2real-noep-unrelated-')}"
    resp = _put_events_with_dns_retry(ctx, events, EndpointId=endpoint_id, Entries=[{
        "EventBusName": unrelated_bus_arn, "Source": "sim2real.bogus", "DetailType": "x",
        "Detail": json.dumps({"a": 1}),
    }])
    assert resp["FailedEntryCount"] == 1, (
        f"expected PutEvents with an EventBusName outside the endpoint's own buses to fail "
        f"that entry, got {resp['Entries']!r}"
    )
    entry = resp["Entries"][0]
    assert entry["ErrorCode"] == "InvalidArgument", f"unexpected error code: {entry!r}"
    assert entry["ErrorMessage"] == (
        f"Parameter EventBusName is not valid. Reason: The endpoint is not associated with "
        f"the event bus {unrelated_bus_arn}."
    ), f"unexpected error message: {entry!r}"

    # positive control: the same call shape, naming one of the endpoint's own buses, still
    # succeeds and actually delivers -- the negative above did not disturb the real endpoint.
    source = _put_rule_with_target(ctx, events, queue_url, queue_arn)
    marker = ctx.unique_name("m-")
    resp = _put_events_with_dns_retry(ctx, events, EndpointId=endpoint_id, Entries=[{
        "EventBusName": primary_bus_arn, "Source": source, "DetailType": "x",
        "Detail": json.dumps({"marker": marker}),
    }])
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
    _poll_for_marker(ctx, queue_url, marker, cap_s=90.0)


def _create_endpoint(ctx, partition: str) -> tuple[str, str]:
    """A cheap, always-healthy global endpoint: a CALCULATED health check with no children is
    always healthy, so no CloudWatch alarm is needed for a check that never fails over."""
    events = ctx.client("events")
    route53 = ctx.client("route53")
    home = ctx.region
    away = "us-west-2" if home != "us-west-2" else "us-east-1"
    hc = route53.create_health_check(
        CallerReference=ctx.unique_name("sim2real-behav-noephc-"),
        HealthCheckConfig={"Type": "CALCULATED", "HealthThreshold": 0},
    )
    hc_id = hc["HealthCheck"]["Id"]
    ctx.on_cleanup(_teardown(lambda: route53.delete_health_check(HealthCheckId=hc_id), "NoSuchHealthCheck"))
    route53.change_tags_for_resource(ResourceType="healthcheck", ResourceId=hc_id,
                                     AddTags=[{"Key": "sim2real", "Value": CHECK}])
    health_check_arn = f"arn:{partition}:route53:::healthcheck/{hc_id}"

    primary_bus_arn = f"arn:{partition}:events:{home}:{ctx.account}:event-bus/default"
    secondary_bus_arn = f"arn:{partition}:events:{away}:{ctx.account}:event-bus/default"
    name = ctx.unique_name("sim2real-behav-noep-")
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
                        lambda r: r.get("State") == "ACTIVE", cap_s=180.0,
                        description=f"endpoint {name} ACTIVE")
    return final["EndpointId"], primary_bus_arn


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-noepq-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _put_rule_with_target(ctx, events, queue_url: str, queue_arn: str) -> str:
    rule_name = ctx.unique_name("sim2real-behav-noeprule-")
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps({"source": [rule_name]}),
                               State="ENABLED", Tags=[{"Key": "sim2real", "Value": CHECK}])["RuleArn"]

    def _delete_rule() -> None:
        try:
            events.remove_targets(Rule=rule_name, Ids=["sim2real-target"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_teardown(_delete_rule, "ResourceNotFoundException"))
    sqs = ctx.client("sqs")
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    resp = events.put_targets(Rule=rule_name, Targets=[{"Id": "sim2real-target", "Arn": queue_arn}])
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed: {resp['FailedEntries']!r}"
    return rule_name


def _put_events_with_dns_retry(ctx, events, **kwargs) -> dict:
    """PutEvents, retried while the endpoint's DNS name does not resolve yet."""
    timeout_s = _budget_s(ctx, _DNS_PROPAGATION_TIMEOUT_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return events.put_events(**kwargs)
        except EndpointConnectionError as exc:
            if time.monotonic() >= deadline:
                raise _expired(ctx, "the endpoint's DNS name resolving for PutEvents",
                               timeout_s, f"last error: {exc}") from exc
            time.sleep(10.0)


def _poll_for_marker(ctx, queue_url: str, marker: str, cap_s: float) -> dict:
    """Receive and delete until the event carrying marker arrives; return its envelope."""
    sqs = ctx.client("sqs")
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while (remaining := deadline - time.monotonic()) > 0:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=max(1, min(5, int(remaining))))
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body.get("detail"), dict) and body["detail"].get("marker") == marker:
                return body
    raise _expired(ctx, f"an event carrying marker {marker!r} reaching {queue_url}", timeout_s, "none seen")


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
