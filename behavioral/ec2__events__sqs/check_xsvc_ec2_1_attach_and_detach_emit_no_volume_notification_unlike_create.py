"""xsvc-ec2-1-attach-and-detach-emit-no-volume-notification-unlike-create."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-ec2-1-attach-and-detach-emit-no-volume-notification-unlike-create"
GROUP = "event-propagation"
SERVICES = ["ec2", "events", "sqs"]

_SOURCE = "aws.ec2"
_DETAIL_TYPE = "EBS Volume Notification"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.93.0.0/16"
_SUBNET_CIDR = "10.93.1.0/24"
_REPAIR_ATTEMPTS = 4


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:eventing",
      "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateVolume emits an EBS Volume Notification (createVolume, available) but a successful attach and
    detach emit none: a rule pinned to `attachVolume` stays silent while an unpinned rule gets exactly the
    createVolume, and re-patterning the pinned rule to createVolume makes it deliver."""
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-ec2-1-att-")
    started_at = datetime.now(timezone.utc)

    subnet, az = _network(ctx, ec2, name)
    instance = _launch(ctx, ec2, _ami(ctx), subnet, name + "-i")

    all_q = _wire(ctx, events, sqs, account, name + "-all", {
        "source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})
    pin_rule = (name + "-pin")[:64]
    pin_q = _wire(ctx, events, sqs, account, name + "-pin", {
        "source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
        "detail": {"event": ["attachVolume"]}})
    _prove_pipeline(ctx, events, sqs, account, name)

    _poll(lambda: _state(ec2, instance), lambda s: s == "running", timeout_s=600.0,
          interval_s=5.0, what=f"instance {instance} reaching 'running'")

    # --- the subject volume: created, attached, detached ---
    vol = _create_volume(ctx, ec2, az, name + "-v")
    arn_v = _vol_arn(ctx.region, account, vol)
    got_all: list = []
    _collect(sqs, all_q, got_all, lambda g: _has(g, arn_v, "createVolume"),
             what=f"the createVolume notification for {vol} on the unpinned rule")

    ec2.attach_volume(VolumeId=vol, InstanceId=instance, Device="/dev/sdf")
    att = _poll(lambda: _attachment(ec2, vol), lambda a: a[0] == "in-use" and a[1] == "attached",
                timeout_s=300.0, interval_s=3.0,
                what=f"volume {vol} reaching in-use/attached after AttachVolume")
    assert att[2] == instance, f"{vol} must be attached to {instance}, DescribeVolumes said {att!r}"
    ec2.detach_volume(VolumeId=vol)
    _poll(lambda: _attachment(ec2, vol), lambda a: a[0] == "available", timeout_s=300.0,
          interval_s=3.0, what=f"volume {vol} returning to 'available' after DetachVolume")

    # --- barrier: a later volume's createVolume reaches the unpinned rule ---
    barrier = _create_volume(ctx, ec2, az, name + "-b")
    arn_b = _vol_arn(ctx.region, account, barrier)
    _collect(sqs, all_q, got_all, lambda g: _has(g, arn_b, "createVolume"),
             what=f"the barrier volume {barrier}'s createVolume notification")
    for _ in range(3):
        got_all.extend(_drain(sqs, all_q))
    pinned: list = []
    for _ in range(2):
        pinned.extend(_drain(sqs, pin_q))

    mine = [e for e in got_all if arn_v in e.get("resources", [])]
    seen = sorted({e["detail"].get("event") for e in mine})
    assert seen == ["createVolume"], (
        f"a successful attach and detach must emit no EBS Volume Notification; for {vol} the "
        f"unpinned rule delivered events {seen!r}: {[e['detail'] for e in mine]!r}"
    )
    ours = [e for e in pinned if {arn_v, arn_b} & set(e.get("resources", []))]
    assert ours == [], (
        f"the rule pinned to detail.event 'attachVolume' must receive nothing for {vol}/{barrier} "
        f"(neither the createVolume nor the successful attach); it delivered "
        f"{[(e['resources'], e['detail']) for e in ours]!r}"
    )
    for env in [e for e in got_all if {arn_v, arn_b} & set(e.get("resources", []))]:
        arn = arn_v if arn_v in env["resources"] else arn_b
        detail = env["detail"]
        assert (detail.get("event"), detail.get("result"), detail.get("cause")) == (
            "createVolume", "available", ""), (
            f"a successful createVolume reports result 'available' with an empty cause; got "
            f"{detail!r}"
        )
        assert isinstance(detail.get("request-id"), str) and detail["request-id"], (
            f"createVolume must carry the request-id of the CreateVolume call: {detail!r}"
        )
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_DETAIL_TYPE,
                         resources=[arn], started_at=started_at)
    _assert_distinct_ids([e for e in got_all if {arn_v, arn_b} & set(e.get("resources", []))])

    # --- repair exactly one thing: the pinned rule's pattern. The same queue must now receive. ---
    events.put_rule(Name=pin_rule, State="ENABLED", EventPattern=json.dumps({
        "source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
        "detail": {"event": ["createVolume"]}}),
        Description="sim2real xsvc-ec2-1 check (repaired)")
    delivered = None
    for attempt in range(_REPAIR_ATTEMPTS):
        probe = _create_volume(ctx, ec2, az, f"{name}-r{attempt}")
        arn_p = _vol_arn(ctx.region, account, probe)
        deadline = time.monotonic() + 120.0
        while time.monotonic() < deadline and not _has(pinned, arn_p, "createVolume"):
            pinned.extend(_drain(sqs, pin_q))
        if _has(pinned, arn_p, "createVolume"):
            delivered = arn_p
            break
    assert delivered, (
        f"after re-patterning {pin_rule} to createVolume, none of {_REPAIR_ATTEMPTS} new volumes' "
        f"createVolume reached its queue; it holds {[(e['resources'], e['detail']) for e in pinned]!r}"
        f". The queue or rule was never reachable, so the earlier silence proved nothing"
    )
    still = [e for e in pinned if {arn_v, arn_b} & set(e.get("resources", []))]
    assert still == [], f"the pre-repair volumes must never reach the pinned queue: {still!r}"


def _vol_arn(region, account, vol):
    return f"arn:aws:ec2:{region}:{account}:volume/{vol}"


def _has(envs, arn, event):
    return any(arn in e.get("resources", []) and e.get("detail", {}).get("event") == event
               for e in envs)


def _attachment(ec2, vol):
    try:
        vols = ec2.describe_volumes(VolumeIds=[vol])["Volumes"]
    except ClientError as exc:
        if _code(exc) == "InvalidVolume.NotFound":
            return ("__gone__", None, None)
        raise
    if not vols:
        return ("__gone__", None, None)
    atts = vols[0].get("Attachments") or []
    if not atts:
        return (vols[0]["State"], None, None)
    return (vols[0]["State"], atts[0].get("State"), atts[0].get("InstanceId"))


def _vol_state(ec2, vol):
    return _attachment(ec2, vol)[0]


def _delete_volume(ec2, vol):
    state = _vol_state(ec2, vol)
    if state == "__gone__":
        return
    if state == "in-use":
        ec2.detach_volume(VolumeId=vol, Force=True)
        _poll(lambda: _vol_state(ec2, vol), lambda s: s in ("available", "__gone__"),
              timeout_s=300.0, interval_s=5.0,
              what=f"volume {vol} detaching during cleanup")
    try:
        ec2.delete_volume(VolumeId=vol)
    except ClientError as exc:
        if _code(exc) != "InvalidVolume.NotFound":
            raise


def _create_volume(ctx, ec2, az, name):
    vol = ec2.create_volume(AvailabilityZone=az, Size=1, VolumeType="gp3", TagSpecifications=[
        {"ResourceType": "volume", "Tags": _tags_for(name)}])["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, vol))
    _poll(lambda: _vol_state(ec2, vol), lambda s: s == "available", timeout_s=300.0,
          interval_s=3.0, what=f"volume {vol} reaching 'available'")
    return vol


# ===== helpers =====

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
