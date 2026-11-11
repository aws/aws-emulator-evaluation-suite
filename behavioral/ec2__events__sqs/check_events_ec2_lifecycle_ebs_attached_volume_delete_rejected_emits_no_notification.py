"""events-ec2-lifecycle-ebs-attached-volume-delete-rejected-emits-no-notification."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-ec2-lifecycle-ebs-attached-volume-delete-rejected-emits-no-notification"
GROUP = "event-propagation"
SERVICES = ["ec2", "events", "sqs"]

_SOURCE = "aws.ec2"
_DETAIL_TYPE = "EBS Volume Notification"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.86.0.0/16"
_SUBNET_CIDR = "10.86.1.0/24"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:eventing", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """DeleteVolume on an attached volume fails with VolumeInUse and EC2 emits no deleteVolume event for it,
    while an unattached sibling's delete emits one on the same rule; after detaching, the same volume's
    delete emits deleteVolume with result "deleted"."""
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-evlc-inuse-")
    started_at = datetime.now(timezone.utc)

    subnet, az = _network(ctx, ec2, name)
    instance = _launch(ctx, ec2, _ami(ctx), subnet, name + "-i")
    attached = _create_volume(ctx, ec2, az, name + "-att")
    sibling = _create_volume(ctx, ec2, az, name + "-sib")
    arn_att = f"arn:aws:ec2:{ctx.region}:{account}:volume/{attached}"
    arn_sib = f"arn:aws:ec2:{ctx.region}:{account}:volume/{sibling}"

    _poll(lambda: _state(ec2, instance), lambda s: s == "running", timeout_s=600.0,
          interval_s=5.0, what=f"instance {instance} reaching 'running'")
    for vol in (attached, sibling):
        _poll(lambda v=vol: _vol_state(ec2, v), lambda s: s == "available", timeout_s=300.0,
              interval_s=3.0, what=f"volume {vol} reaching 'available'")
    ec2.attach_volume(VolumeId=attached, InstanceId=instance, Device="/dev/sdf")
    _poll(lambda: _vol_state(ec2, attached), lambda s: s == "in-use", timeout_s=300.0,
          interval_s=3.0, what=f"volume {attached} reaching 'in-use' after AttachVolume")

    queue = _wire(ctx, events, sqs, account, name + "-del", {
        "source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
        "detail": {"event": ["deleteVolume"]}, "resources": [arn_att, arn_sib]})
    _prove_pipeline(ctx, events, sqs, account, name)

    # --- the refusal: exact code, and the volume is untouched ---
    code, message = _error(lambda: ec2.delete_volume(VolumeId=attached),
                           what=f"DeleteVolume on attached volume {attached}")
    assert code == "VolumeInUse", (
        f"deleting an attached volume must be refused with VolumeInUse, got {code!r}"
    )
    expected = f"Volume {attached} is currently attached to {{{instance}}}"
    assert message == expected, f"DeleteVolume refused with {message!r}, expected {expected!r}"
    assert _vol_state(ec2, attached) == "in-use", (
        f"the refused delete must leave {attached} in-use; it is {_vol_state(ec2, attached)!r}"
    )

    # --- positive control on the same wiring ---
    ec2.delete_volume(VolumeId=sibling)
    got: list = []
    _collect(sqs, queue, got, lambda g: arn_sib in _arns(g),
             what=f"the sibling volume {sibling}'s deleteVolume notification")

    # --- effect-absent, behind that barrier ---
    for _ in range(3):
        got.extend(_drain(sqs, queue))
    assert arn_att not in _arns(got), (
        f"the refused DeleteVolume must emit no deleteVolume for {attached}; the rule delivered "
        f"{[(e['resources'], e['detail']) for e in got]!r}"
    )

    # --- repair exactly one thing: detach. The withheld notification must now arrive. ---
    ec2.detach_volume(VolumeId=attached)
    _poll(lambda: _vol_state(ec2, attached), lambda s: s == "available", timeout_s=300.0,
          interval_s=3.0, what=f"volume {attached} returning to 'available' after DetachVolume")
    ec2.delete_volume(VolumeId=attached)
    _collect(sqs, queue, got, lambda g: arn_att in _arns(g),
             what=f"{attached}'s deleteVolume notification once it was detached")

    for env in got:
        assert (env["detail"]["event"], env["detail"]["result"]) == ("deleteVolume", "deleted"), (
            f"a deleteVolume notification must report result 'deleted': {env['detail']!r}"
        )
        expected = [arn_att] if arn_att in env.get("resources", []) else [arn_sib]
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_DETAIL_TYPE,
                         resources=expected, started_at=started_at)
    _assert_distinct_ids(got)


def _arns(envs):
    return {r for e in envs for r in e.get("resources", [])}


def _error(fn, *, what):
    """The exact (code, message) of a call that must be refused. An ACCEPTED call raises: a target
    that accepts what real AWS refuses must not read as a naming difference."""
    try:
        fn()
    except ClientError as exc:
        return _code(exc), exc.response["Error"].get("Message")
    raise AssertionError(f"{what} was ACCEPTED; real AWS refuses it")


def _create_volume(ctx, ec2, az, name):
    vol = ec2.create_volume(AvailabilityZone=az, Size=1, VolumeType="gp3", TagSpecifications=[
        {"ResourceType": "volume", "Tags": _tags_for(name)}])["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, vol))
    return vol


def _vol_state(ec2, vol):
    try:
        vols = ec2.describe_volumes(VolumeIds=[vol])["Volumes"]
    except ClientError as exc:
        if _code(exc) == "InvalidVolume.NotFound":
            return "__gone__"
        raise
    return vols[0]["State"] if vols else "__gone__"


def _delete_volume(ec2, vol):
    """Cleanup: force-detach if attached, wait until detachable, delete; a gone volume is done."""
    if _vol_state(ec2, vol) == "__gone__":
        return
    if _vol_state(ec2, vol) == "in-use":
        ec2.detach_volume(VolumeId=vol, Force=True)
    _poll(lambda: _vol_state(ec2, vol), lambda s: s in ("available", "__gone__", "error"),
          timeout_s=300.0, interval_s=5.0, what=f"volume {vol} becoming deletable")
    if _vol_state(ec2, vol) != "__gone__":
        ec2.delete_volume(VolumeId=vol)


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
