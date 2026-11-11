"""xsvc-ec2-1-state-change-transformed-delivery-while-rejected-target-dead-letters."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-ec2-1-state-change-transformed-delivery-while-rejected-target-dead-letters"
GROUP = "event-propagation"
SERVICES = ["ec2", "events", "sqs"]

_SOURCE = "aws.ec2"
_DETAIL_TYPE = "EC2 Instance State-change Notification"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.96.0.0/16"
_SUBNET_CIDR = "10.96.1.0/24"
_KIND = "sim2real-transformed"
_TEMPLATE = '{"instance": <iid>, "state": <st>, "kind": "' + _KIND + '"}'
_METRIC_TIMEOUT_S = 600.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "concern:negative-classes",
      "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """One rule fans an instance's state-change events to target A, which receives exactly the
    InputTransformer output, and target B, whose policy refuses EventBridge: B stays empty and each
    event lands in B's dead-letter queue untransformed with ERROR_CODE NO_RESOURCE and the rule/B ARNs."""
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    cloudwatch = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-ec2-1-dlq-")
    started_at = datetime.now(timezone.utc)

    subnet, _az = _network(ctx, ec2, name)
    _prove_pipeline(ctx, events, sqs, account, name)
    instance = _launch(ctx, ec2, _ami(ctx), subnet, name + "-i")
    _poll(lambda: _state(ec2, instance), lambda s: s == "running", timeout_s=600.0,
          interval_s=5.0, what=f"instance {instance} reaching 'running'")

    rule = (name + "-sc")[:64]
    rule_arn = f"arn:aws:events:{ctx.region}:{account}:rule/{rule}"
    good_url, good_arn = _queue(ctx, sqs, name + "-tx")
    bad_url, bad_arn = _queue(ctx, sqs, name + "-rej")
    dlq_url, dlq_arn = _queue(ctx, sqs, name + "-dlq")
    _allow_rule(sqs, good_url, good_arn, rule_arn)
    _allow_rule(sqs, dlq_url, dlq_arn, rule_arn)
    put = events.put_rule(Name=rule, State="ENABLED", Description="sim2real xsvc-ec2-1 check",
                          Tags=[{"Key": "sim2real", "Value": "1"}],
                          EventPattern=json.dumps({"source": [_SOURCE],
                                                   "detail-type": [_DETAIL_TYPE],
                                                   "detail": {"instance-id": [instance]}}))
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, Force=True))
    assert put["RuleArn"] == rule_arn, f"PutRule returned {put['RuleArn']!r}, want {rule_arn!r}"
    resp = events.put_targets(Rule=rule, Targets=[
        {"Id": "tx", "Arn": good_arn,
         "InputTransformer": {"InputPathsMap": {"iid": "$.detail.instance-id",
                                                "st": "$.detail.state"},
                              "InputTemplate": _TEMPLATE}},
        {"Id": "rej", "Arn": bad_arn, "DeadLetterConfig": {"Arn": dlq_arn},
         "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["tx", "rej"], Force=True))
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed: {resp!r}"

    # The transitions under test happen strictly after the rule exists.
    ec2.stop_instances(InstanceIds=[instance])
    _poll(lambda: _state(ec2, instance), lambda s: s == "stopped", timeout_s=600.0,
          interval_s=5.0, what=f"instance {instance} reaching 'stopped'")

    transformed: list = []
    deadline = time.monotonic() + _DRAIN_TIMEOUT_S
    while "stopped" not in {b.get("state") for b in transformed} and time.monotonic() < deadline:
        transformed.extend(_drain_raw(sqs, good_url)[0])
    tx_states = {b.get("state") for b in transformed}
    assert "stopped" in tx_states, (
        f"target A must receive the transformed 'stopped' notification for {instance} within "
        f"{_DRAIN_TIMEOUT_S}s; it received {transformed!r}"
    )
    for body in transformed:
        assert body == {"instance": instance, "state": body.get("state"), "kind": _KIND}, (
            f"target A must receive exactly the rendered InputTemplate (no envelope, no extra "
            f"keys) for {instance}; got {body!r}"
        )
        assert body["state"] in ("pending", "running", "stopping", "stopped"), (
            f"$.detail.state must render a real EC2 state, got {body['state']!r}"
        )

    # Every state A received is dead-lettered for B: same event, same instant, other target.
    dead: list = []
    deadline = time.monotonic() + _DRAIN_TIMEOUT_S
    while not tx_states <= {e.get("detail", {}).get("state") for e, _a in dead} \
            and time.monotonic() < deadline:
        bodies, attrs = _drain_raw(sqs, dlq_url, with_attrs=True)
        dead.extend(zip(bodies, attrs))
    dead_states = {e.get("detail", {}).get("state") for e, _a in dead}
    assert tx_states <= dead_states, (
        f"every state delivered to A ({sorted(tx_states)!r}) must also be dead-lettered for the "
        f"rejecting target; the DLQ holds {sorted(dead_states)!r}"
    )
    for env, attrs in dead:
        assert env.get("detail") == {"instance-id": instance, "state": env["detail"].get("state")}, (
            f"the DLQ holds the ORIGINAL untransformed event for {instance}; got {env!r}"
        )
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_DETAIL_TYPE,
                         resources=[f"arn:aws:ec2:{ctx.region}:{account}:instance/{instance}"],
                         started_at=started_at)
        got_attrs = {k: v.get("StringValue") for k, v in attrs.items()}
        assert got_attrs.get("ERROR_CODE") == "NO_RESOURCE", (
            f"a queue that grants EventBridge nothing is dead-lettered with ERROR_CODE "
            f"'NO_RESOURCE'; got {got_attrs!r}"
        )
        assert got_attrs.get("RULE_ARN") == rule_arn and got_attrs.get("TARGET_ARN") == bad_arn, (
            f"DLQ attributes must name rule {rule_arn!r} and target {bad_arn!r}; got {got_attrs!r}"
        )
        assert got_attrs.get("ERROR_MESSAGE"), f"ERROR_MESSAGE must be present: {got_attrs!r}"
    _assert_distinct_ids([e for e, _a in dead])

    # Effect absent: the rejecting target received nothing, behind the barrier above.
    leaked = []
    for _ in range(2):
        leaked.extend(_drain_raw(sqs, bad_url)[0])
    assert leaked == [], f"the rejecting target must receive nothing; it holds {leaked!r}"

    window = (started_at - timedelta(minutes=5), datetime.now(timezone.utc) + timedelta(minutes=5))
    # Telemetry follows the delivery path: each rejected, dead-lettered delivery is counted.
    _poll(lambda: _metric_sum(cloudwatch, "FailedInvocations", rule, window),
          lambda v: v >= 1, timeout_s=_METRIC_TIMEOUT_S, interval_s=20.0,
          what=f"AWS/Events FailedInvocations for {rule} reaching >= 1")
    _poll(lambda: _metric_sum(cloudwatch, "InvocationsSentToDlq", rule, window),
          lambda v: v >= 1, timeout_s=_METRIC_TIMEOUT_S, interval_s=20.0,
          what=f"AWS/Events InvocationsSentToDlq for {rule} reaching >= 1")


def _queue(ctx, sqs, name):
    url = sqs.create_queue(QueueName=name[:80],
                           Attributes={"ReceiveMessageWaitTimeSeconds": "10"},
                           tags={"sim2real": "1"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"]
    return url, arn


def _allow_rule(sqs, url, arn, rule_arn):
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})


def _drain_raw(sqs, url, wait=10, with_attrs=False):
    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait,
                               MessageAttributeNames=["All"]).get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    bodies = [json.loads(m["Body"]) for m in msgs]
    attrs = [m.get("MessageAttributes") or {} for m in msgs]
    return (bodies, attrs) if with_attrs else (bodies, None)


def _metric_sum(cloudwatch, metric, rule, window):
    points = cloudwatch.get_metric_statistics(
        Namespace="AWS/Events", MetricName=metric,
        Dimensions=[{"Name": "RuleName", "Value": rule}],
        StartTime=window[0], EndTime=window[1], Period=60, Statistics=["Sum"])["Datapoints"]
    return sum(p["Sum"] for p in points)


_DRAIN_TIMEOUT_S = 600.0
_CLOCK_SLACK_S = 300
_ISO_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidInstanceID.NotFound")


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    """Bounded poll that RAISES on timeout — never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _retry_dependency(fn, attempts=30, delay=10.0):
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE:
                return
            if _code(exc) != "DependencyViolation" or attempt == attempts - 1:
                raise
            time.sleep(delay)


def _zones_offering(ec2, instance_type):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    return usable


def _network(ctx, ec2, name):
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc)))
    az = _zones_offering(ec2, _INSTANCE_TYPE)[0]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags_for(name)}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet, az


def _ami(ctx):
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    return ami


def _launch(ctx, ec2, ami, subnet, name):
    iid = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
        TagSpecifications=[{"ResourceType": "instance", "Tags": _tags_for(name)},
                           {"ResourceType": "volume", "Tags": _tags_for(name)}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, iid))
    return iid


def _terminate_and_wait(ec2, iid):
    try:
        ec2.terminate_instances(InstanceIds=[iid])
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    _poll(lambda: _state(ec2, iid), lambda s: s in ("terminated", "__gone__"), timeout_s=600.0,
          interval_s=10.0, what=f"instance {iid} reaching 'terminated' during cleanup")


def _state(ec2, iid):
    try:
        resv = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _wire(ctx, events, sqs, account, name, pattern):
    """One SQS queue, a default-bus rule, and the rule->queue target. Returns the queue URL."""
    url = sqs.create_queue(QueueName=name[:80],
                           Attributes={"ReceiveMessageWaitTimeSeconds": "10"},
                           tags={"sim2real": "1"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    rule = name[:64]
    rule_arn = events.put_rule(Name=rule, EventPattern=json.dumps(pattern), State="ENABLED",
                               Description="sim2real xsvc-ec2-1 check",
                               Tags=[{"Key": "sim2real", "Value": "1"}])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, Force=True))
    assert rule_arn == f"arn:aws:events:{ctx.region}:{account}:rule/{rule}", (
        f"PutRule returned rule ARN {rule_arn!r}"
    )
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    resp = events.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["q"], Force=True))
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed for {rule}: {resp!r}"
    return url


def _drain(sqs, url, wait=10):
    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                               WaitTimeSeconds=wait).get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return [json.loads(m["Body"]) for m in msgs]


def _collect(sqs, url, into, done, *, what):
    deadline = time.monotonic() + _DRAIN_TIMEOUT_S
    while not done(into) and time.monotonic() < deadline:
        into.extend(_drain(sqs, url))
    assert done(into), (
        f"{what}: not delivered within {_DRAIN_TIMEOUT_S}s. Received "
        f"{[(e.get('detail-type'), e.get('time'), e.get('detail')) for e in into]!r}. A target "
        f"that never emits its own events fails exactly here"
    )


def _prove_pipeline(ctx, events, sqs, account, name):
    """Positive control on a SEPARATE rule: EventBridge -> SQS delivers in this account right now.
    PutEvents is used ONLY here — never for the event under test."""
    source = "sim2real.control"
    nonce = ctx.unique_name("nonce-")
    url = _wire(ctx, events, sqs, account, name + "-ctl",
                {"source": [source], "detail": {"nonce": [nonce]}})

    def attempt():
        resp = events.put_events(Entries=[{"Source": source, "DetailType": "sim2real control",
                                           "Detail": json.dumps({"nonce": nonce})}])
        assert resp["FailedEntryCount"] == 0, f"control PutEvents failed: {resp!r}"
        return [e for e in _drain(sqs, url) if e.get("detail", {}).get("nonce") == nonce]

    got = _poll(attempt, bool, timeout_s=240.0, interval_s=2.0,
                what="the PutEvents positive control reaching its own queue")
    assert got[0]["source"] == source and got[0]["account"] == account, (
        f"control event arrived with the wrong envelope: {got[0]!r}"
    )


def _stamp(env):
    raw = env.get("time")
    assert isinstance(raw, str) and _ISO_SECONDS.match(raw), (
        f"event time must be an ISO-8601 UTC instant like 2026-01-01T00:00:00Z, got {raw!r}"
    )
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _assert_envelope(ctx, account, env, *, source, detail_type, resources, started_at):
    assert env.get("version") == "0", f"envelope version must be '0', got {env.get('version')!r}"
    assert env.get("source") == source, f"expected source {source!r}, got {env.get('source')!r}"
    assert env.get("detail-type") == detail_type, (
        f"expected detail-type {detail_type!r}, got {env.get('detail-type')!r}"
    )
    assert env.get("account") == account, (
        f"expected account {account!r}, got {env.get('account')!r}"
    )
    assert env.get("region") == ctx.region, (
        f"expected region {ctx.region!r}, got {env.get('region')!r}"
    )
    assert env.get("resources") == resources, (
        f"expected resources {resources!r}, got {env.get('resources')!r}"
    )
    assert isinstance(env.get("id"), str) and _UUID.match(env["id"]), (
        f"event id must be a UUID, got {env.get('id')!r}"
    )
    stamped = _stamp(env)
    floor = started_at - timedelta(seconds=_CLOCK_SLACK_S)
    ceiling = datetime.now(timezone.utc) + timedelta(seconds=_CLOCK_SLACK_S)
    assert floor <= stamped <= ceiling, (
        f"event time {env['time']!r} must fall inside this run's window "
        f"[{floor.isoformat()}, {ceiling.isoformat()}]"
    )


def _assert_distinct_ids(envs):
    """At-least-once delivery may repeat an event (same id, same payload). Two DIFFERENT events
    must never share an id, and every distinct event must carry its own."""
    by_id: dict = {}
    for env in envs:
        payload = json.dumps({k: env.get(k) for k in ("detail-type", "resources", "detail")},
                             sort_keys=True)
        prior = by_id.setdefault(env["id"], payload)
        assert prior == payload, (
            f"id {env['id']!r} was carried by two different events: {prior} and {payload}"
        )
    distinct_payloads = {json.dumps({k: e.get(k) for k in ("detail-type", "resources", "detail")},
                                    sort_keys=True) for e in envs}
    assert len(by_id) == len(distinct_payloads), (
        f"{len(distinct_payloads)} distinct events arrived under {len(by_id)} ids"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
