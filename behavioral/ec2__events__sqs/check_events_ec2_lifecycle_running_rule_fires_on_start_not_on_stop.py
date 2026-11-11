"""events-ec2-lifecycle-running-rule-fires-on-start-not-on-stop."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-ec2-lifecycle-running-rule-fires-on-start-not-on-stop"
GROUP = "event-propagation"
SERVICES = ["ec2", "events", "sqs"]

_SOURCE = "aws.ec2"
_DETAIL_TYPE = "EC2 Instance State-change Notification"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.83.0.0/16"
_SUBNET_CIDR = "10.83.1.0/24"


@tags("axis:happy-path", "cap:c4", "concern:eventing", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule on detail.state=running delivers exactly instance A's EC2-emitted running event and nothing
    for instance B, which only reaches stopped; a broad rule over the same wiring delivers B's stopped
    event first, and both rules carry the same event ids for A."""
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-evlc-run-")
    started_at = datetime.now(timezone.utc)

    subnet, _az = _network(ctx, ec2, name)
    ami = _ami(ctx)
    inst_a = _launch(ctx, ec2, ami, subnet, name + "-a")
    inst_b = _launch(ctx, ec2, ami, subnet, name + "-b")
    for iid in (inst_a, inst_b):
        _poll(lambda i=iid: _state(ec2, i), lambda s: s == "running", timeout_s=600.0,
              interval_s=5.0, what=f"instance {iid} reaching 'running' after RunInstances")

    running_q = _wire(ctx, events, sqs, account, name + "-run", {
        "source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
        "detail": {"state": ["running"], "instance-id": [inst_a, inst_b]}})
    broad_q = _wire(ctx, events, sqs, account, name + "-all", {
        "source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
        "detail": {"instance-id": [inst_a, inst_b]}})
    _prove_pipeline(ctx, events, sqs, account, name)

    # Every event this check asserts on is stamped at or after this instant; the launch's own
    # pending/running events predate the rules and are excluded by their own `time` field.
    acted_at = datetime.now(timezone.utc).replace(microsecond=0)

    # --- leg 1: stop BOTH. B will only ever reach `stopped` from here on. ---
    ec2.stop_instances(InstanceIds=[inst_a, inst_b])
    for iid in (inst_a, inst_b):
        _poll(lambda i=iid: _state(ec2, i), lambda s: s == "stopped", timeout_s=600.0,
              interval_s=5.0, what=f"instance {iid} reaching 'stopped'")
    broad: list = []
    _collect(sqs, broad_q, broad,
             lambda got: {(inst_a, "stopped"), (inst_b, "stopped")} <= _pairs(got, acted_at),
             what="the broad rule delivering both instances' `stopped` event")

    # --- leg 2: start ONLY A. The running rule must fire for A. ---
    ec2.start_instances(InstanceIds=[inst_a])
    _poll(lambda: _state(ec2, inst_a), lambda s: s == "running", timeout_s=600.0,
          interval_s=5.0, what=f"instance {inst_a} reaching 'running' after StartInstances")
    running: list = []
    _collect(sqs, running_q, running,
             lambda got: (inst_a, "running") in _pairs(got, acted_at),
             what=f"the running rule delivering {inst_a}'s `running` event")
    _collect(sqs, broad_q, broad,
             lambda got: {(inst_a, "pending"), (inst_a, "running")} <= _pairs(got, acted_at),
             what=f"the broad rule delivering {inst_a}'s `pending` and `running` events")

    # --- leg 3: effect-absent. The barrier above has delivered B's `stopped` and A's `running`
    # over the identical wiring; three further long polls must still add nothing for B. ---
    for _ in range(3):
        running.extend(_drain(sqs, running_q))
    fresh_running = _fresh(running, acted_at)
    assert _pairs(fresh_running, acted_at) == {(inst_a, "running")}, (
        f"the running rule must have delivered exactly A's running state and nothing for B (which "
        f"only reached 'stopped'); it delivered {sorted(_pairs(fresh_running, acted_at))!r}"
    )
    assert _state(ec2, inst_b) == "stopped", (
        f"instance B must still be stopped for its absence to mean anything; it is "
        f"{_state(ec2, inst_b)!r}"
    )

    # --- the envelope, on every EC2-emitted event this check caused ---
    fresh_broad = _fresh(broad, acted_at)
    for env in fresh_broad + fresh_running:
        iid = env["detail"]["instance-id"]
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_DETAIL_TYPE,
                         resources=[f"arn:aws:ec2:{ctx.region}:{account}:instance/{iid}"],
                         started_at=started_at)
    _assert_distinct_ids(fresh_broad)
    _assert_distinct_ids(fresh_running)
    ids_broad = {e["id"] for e in fresh_broad if (e["detail"]["instance-id"], e["detail"]["state"])
                 == (inst_a, "running")}
    ids_running = {e["id"] for e in fresh_running}
    assert ids_broad == ids_running, (
        f"the SAME EC2 event fanned out to two rules must carry the same id; broad rule saw "
        f"{sorted(ids_broad)!r}, running rule saw {sorted(ids_running)!r}"
    )


def _pairs(envs, acted_at):
    return {(e["detail"]["instance-id"], e["detail"]["state"]) for e in _fresh(envs, acted_at)}


def _fresh(envs, acted_at):
    return [e for e in envs if _stamp(e) >= acted_at]


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


def _launch(ctx, ec2, ami, subnet, name, protected=False):
    iid = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
        DisableApiTermination=protected,
        TagSpecifications=[{"ResourceType": "instance", "Tags": _tags_for(name)},
                           {"ResourceType": "volume", "Tags": _tags_for(name)}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, iid))
    return iid


def _terminate_and_wait(ec2, iid):
    try:
        ec2.modify_instance_attribute(InstanceId=iid, DisableApiTermination={"Value": False})
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
                               Description="sim2real events-ec2-lifecycle check",
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
