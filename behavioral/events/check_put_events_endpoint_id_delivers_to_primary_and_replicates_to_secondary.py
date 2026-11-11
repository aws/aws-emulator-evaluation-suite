"""put-events-endpoint-id-delivers-to-primary-and-replicates-to-secondary."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, EndpointConnectionError

from behavioral_harness import tags

CHECK = "put-events-endpoint-id-delivers-to-primary-and-replicates-to-secondary"
GROUP = "global-endpoints"
SERVICES = ["events"]


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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents with EndpointId delivers to the primary bus's rule target; with replication
    enabled a second copy reaches the secondary bus's rule target, carrying the origin Region
    (not the Region it was delivered to) in `region` and the endpoint's own ARN in `resources`.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-global-endpoints.html
    """
    events = ctx.client("events")
    home = ctx.region
    # A global endpoint's FailoverConfig requires a real, distinct secondary Region; the
    # literal here is "any Region other than the check's own", not a pin to a specific one.
    away = "us-west-2" if home != "us-west-2" else "us-east-1"
    events_away = ctx.client("events", region=away)

    alarm_name, cw = _create_controlled_alarm(ctx)
    role_arn, primary_bus_arn, secondary_bus_arn = _create_replication_role(ctx, home, away)
    health_check_arn = _create_cloudwatch_metric_health_check(ctx, alarm_name, role_arn.split(":")[1])

    name = ctx.unique_name("sim2real-behav-gep-")
    # IAM propagation: CreateEndpoint validates the replication role's trust policy at call time,
    # and a role just created can briefly fail that check before it is visible everywhere.
    _create_endpoint_with_role_retry(
        ctx, events, name=name,
        RoutingConfig={"FailoverConfig": {
            "Primary": {"HealthCheck": health_check_arn},
            "Secondary": {"Route": away},
        }},
        EventBuses=[{"EventBusArn": primary_bus_arn}, {"EventBusArn": secondary_bus_arn}],
        ReplicationConfig={"State": "ENABLED"},
        RoleArn=role_arn,
    )
    ctx.on_cleanup(_teardown(lambda: events.delete_endpoint(Name=name), "ResourceNotFoundException"))

    final = _poll_until(ctx, lambda: events.describe_endpoint(Name=name),
                        lambda r: r.get("State") == "ACTIVE", cap_s=180.0,
                        description=f"endpoint {name} ACTIVE")
    endpoint_arn, endpoint_id = final["Arn"], final["EndpointId"]

    source = ctx.unique_name("sim2real.geprep.")
    detail_type = "sim2real-global-endpoint-replication"
    home_queue_url, home_queue_arn = _create_queue(ctx, home)
    _put_rule_with_target(ctx, events, home, source, home_queue_url, home_queue_arn)
    away_queue_url, away_queue_arn = _create_queue(ctx, away)
    _put_rule_with_target(ctx, events_away, away, source, away_queue_url, away_queue_arn)

    marker = ctx.unique_name("m-")
    put_resp = _put_events_with_dns_retry(ctx, events, EndpointId=endpoint_id, Entries=[{
        "EventBusName": primary_bus_arn, "Source": source, "DetailType": detail_type,
        "Detail": json.dumps({"marker": marker}),
    }])
    assert put_resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {put_resp['Entries']!r}"

    home_env = _poll_for_marker(ctx, home, home_queue_url, marker, cap_s=90.0)
    assert home_env["source"] == source and home_env["detail-type"] == detail_type, (
        f"primary delivery does not carry the original event: {home_env!r}"
    )
    assert home_env["region"] == home, (
        f"the primary copy's region should be {home!r}, got {home_env.get('region')!r}"
    )
    assert home_env.get("resources") == [endpoint_arn], (
        "PutEvents through a global endpoint stamps the endpoint's own ARN into `resources`, "
        f"got {home_env.get('resources')!r}, expected {[endpoint_arn]!r}"
    )

    away_env = _poll_for_marker(ctx, away, away_queue_url, marker, cap_s=240.0)
    assert away_env["source"] == source and away_env["detail-type"] == detail_type, (
        f"replicated event does not carry the original event: {away_env!r}"
    )
    assert away_env["account"] == ctx.account, (
        f"replicated event account {away_env.get('account')!r}, expected {ctx.account!r}"
    )
    assert away_env["region"] == home, (
        "a replicated event's `region` names the Region it was replicated FROM (the primary), "
        f"got {away_env.get('region')!r}, expected {home!r}"
    )
    assert away_env.get("resources") == [endpoint_arn], (
        "a replicated event's `resources` carries the global endpoint's own ARN, got "
        f"{away_env.get('resources')!r}, expected {[endpoint_arn]!r}"
    )


def _create_controlled_alarm(ctx):
    """A metric alarm with no real data source, so its state only ever changes via SetAlarmState."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-gealarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real/gerep"),
        MetricName=ctx.unique_name("latency-"),
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="ignore",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="sim2real initial state")
    return alarm_name, cw


def _create_cloudwatch_metric_health_check(ctx, alarm_name: str, partition: str) -> str:
    route53 = ctx.client("route53")
    resp = route53.create_health_check(
        CallerReference=ctx.unique_name("sim2real-behav-gehc-"),
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


def _create_replication_role(ctx, home: str, away: str) -> tuple[str, str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-gerole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    partition = role_arn.split(":")[1]
    primary_bus_arn = f"arn:{partition}:events:{home}:{ctx.account}:event-bus/default"
    secondary_bus_arn = f"arn:{partition}:events:{away}:{ctx.account}:event-bus/default"
    iam.put_role_policy(RoleName=role_name, PolicyName="replicate", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {
                "Effect": "Allow",
                "Action": ["events:PutEvents", "events:PutRule", "events:PutTargets",
                           "events:RemoveTargets", "events:DeleteRule", "events:DescribeRule"],
                "Resource": [primary_bus_arn, secondary_bus_arn,
                            f"arn:{partition}:events:{home}:{ctx.account}:rule/*",
                            f"arn:{partition}:events:{away}:{ctx.account}:rule/*"],
            },
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn},
        ]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="replicate"),
                             "NoSuchEntity"))
    return role_arn, primary_bus_arn, secondary_bus_arn


#: A freshly created endpoint's own DNS name is not resolvable right away; AWS documents an RTO
#: of up to 420 s for a global endpoint to start serving, and plain post-create DNS propagation
#: is the same order of magnitude.
_DNS_PROPAGATION_TIMEOUT_S = 900.0


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


def _create_endpoint_with_role_retry(ctx, events, *, name: str, cap_s: float = 60.0, **kwargs) -> dict:
    """CreateEndpoint, retried only while the new replication role cannot be assumed yet."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return events.create_endpoint(Name=name, **kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "ValidationException" or "cannot be assumed" not in err.get("Message", ""):
                raise
            if time.monotonic() >= deadline:
                raise _expired(ctx, "the replication role assumable by CreateEndpoint", timeout_s,
                               f"last error: {err.get('Message')!r}") from exc
            time.sleep(2.0)


def _create_queue(ctx, region: str) -> tuple[str, str]:
    sqs = ctx.client("sqs", region=region)
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-geq-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _put_rule_with_target(ctx, events, region: str, source: str, queue_url: str, queue_arn: str) -> str:
    rule_name = ctx.unique_name("sim2real-behav-gerule-")
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


def _poll_for_marker(ctx, region: str, queue_url: str, marker: str, cap_s: float) -> dict:
    """Receive and delete until the event carrying marker arrives; return its envelope."""
    sqs = ctx.client("sqs", region=region)
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
