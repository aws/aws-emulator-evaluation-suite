"""events-ec2-lifecycle-copy-snapshot-from-missing-source-fails-asynchronously."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-ec2-lifecycle-copy-snapshot-from-missing-source-fails-asynchronously"
GROUP = "event-propagation"
SERVICES = ["ec2", "events", "sqs"]

_SOURCE = "aws.ec2"
_DETAIL_TYPE = "EBS Snapshot Notification"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.88.0.0/16"
_SUBNET_CIDR = "10.88.1.0/24"
_NOT_FOUND = "Source snapshot is not found"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:eventing", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopySnapshot from a deleted source snapshot is accepted, then the copy goes to State=error
    'Source snapshot is not found' and EC2 emits copySnapshot/failed naming the deleted source; a
    copy of a live snapshot emits copySnapshot/succeeded on the same rule (positive control).
    """
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-evlc-copy-")
    started_at = datetime.now(timezone.utc)

    queue = _wire(ctx, events, sqs, account, name + "-copy", {
        "source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
        "detail": {"event": ["copySnapshot"]}})
    _prove_pipeline(ctx, events, sqs, account, name)

    vol = _source_volume(ctx, ec2, name)
    source = _snapshot(ctx, ec2, vol, name)
    _poll(lambda: _snap_state(ec2, source), lambda s: s[0] == "completed",
          timeout_s=_budget_s(ctx, 900.0), ctx=ctx, interval_s=1.0,
          what=f"source snapshot {source} reaching 'completed'")

    # Positive control: a copy of a live snapshot.
    good = ec2.copy_snapshot(SourceSnapshotId=source, SourceRegion=ctx.region,
                             Description="sim2real events-ec2-lifecycle copy",
                             TagSpecifications=[{"ResourceType": "snapshot",
                                                 "Tags": _tags_for(name)}])["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ec2, good))

    # The fault: a real id whose snapshot was deleted (a fabricated id is refused synchronously
    # with InvalidParameterValue).
    missing = _snapshot(ctx, ec2, vol, name + "-gone")
    _poll(lambda: _snap_state(ec2, missing), lambda s: s[0] == "completed",
          timeout_s=_budget_s(ctx, 900.0), ctx=ctx, interval_s=1.0,
          what=f"to-be-deleted snapshot {missing} reaching 'completed'")
    ec2.delete_snapshot(SnapshotId=missing)
    _poll(lambda: _snap_state(ec2, missing), lambda s: s[0] == "__gone__",
          timeout_s=_budget_s(ctx, 300.0), ctx=ctx, interval_s=1.0,
          what=f"deleted snapshot {missing} disappearing from DescribeSnapshots")
    try:
        bad = ec2.copy_snapshot(SourceSnapshotId=missing, SourceRegion=ctx.region,
                                Description="sim2real events-ec2-lifecycle missing-source copy",
                                TagSpecifications=[{"ResourceType": "snapshot",
                                                    "Tags": _tags_for(name)}])["SnapshotId"]
    except ClientError as exc:
        raise AssertionError(
            f"CopySnapshot from deleted {missing} must be accepted and fail asynchronously; it was "
            f"refused synchronously with {_code(exc)!r}") from exc
    ctx.on_cleanup(lambda: _delete_snapshot(ec2, bad))
    assert bad.startswith("snap-") and bad not in (source, good, missing), (
        f"CopySnapshot must mint a new snapshot id, got {bad!r}"
    )

    _poll(lambda: _snap_state(ec2, good), lambda s: s[0] == "completed",
          timeout_s=_budget_s(ctx, 900.0), ctx=ctx, interval_s=1.0,
          what=f"the control copy {good} reaching 'completed'")
    failed = _poll(lambda: _snap_state(ec2, bad), lambda s: s[0] == "error",
                   timeout_s=_budget_s(ctx, 600.0), ctx=ctx, interval_s=1.0,
                   what=f"the missing-source copy {bad} reaching 'error'")
    assert failed[1] == _NOT_FOUND, (
        f"the failed copy's StateMessage must be {_NOT_FOUND!r}, got {failed[1]!r}"
    )

    good_arn, bad_arn = _snap_arn(ctx.region, good), _snap_arn(ctx.region, bad)
    got: list = []
    _collect(sqs, queue, got,
             lambda g: bool(_snapshots_for(g, good_arn)) and bool(_snapshots_for(g, bad_arn)),
             what=f"copySnapshot notifications for both {good} and {bad}",
             timeout_s=_budget_s(ctx, _DRAIN_TIMEOUT_S), ctx=ctx)

    for env in _snapshots_for(got, good_arn):
        d = env["detail"]
        assert (d.get("result"), d.get("cause")) == ("succeeded", ""), (
            f"the control copy must notify succeeded with no cause: {d!r}"
        )
        assert d.get("source") == _snap_arn(ctx.region, source), (
            f"the control copy's source must be {source!r}: {d!r}"
        )
        assert d.get("snapshot_id") == good_arn, f"snapshot_id must be {good_arn!r}: {d!r}"
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_DETAIL_TYPE,
                         resources=[good_arn], started_at=started_at)
    for env in _snapshots_for(got, bad_arn):
        d = env["detail"]
        assert (d.get("result"), d.get("cause")) == ("failed", _NOT_FOUND), (
            f"the missing-source copy must notify failed with cause {_NOT_FOUND!r}: {d!r}"
        )
        assert d.get("source") == _snap_arn(ctx.region, missing), (
            f"the failed copy must name the deleted source {missing!r}: {d!r}"
        )
        assert d.get("snapshot_id") == bad_arn, f"snapshot_id must be {bad_arn!r}: {d!r}"
        _ms_stamp(d.get("startTime"), "detail.startTime")
        _ms_stamp(d.get("endTime"), "detail.endTime")
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_DETAIL_TYPE,
                         resources=[bad_arn], started_at=started_at)
    _assert_distinct_ids(_snapshots_for(got, good_arn) + _snapshots_for(got, bad_arn))


_MS_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _ms_stamp(raw, what):
    assert isinstance(raw, str) and _MS_ISO.match(raw), (
        f"{what} must be an ISO-8601 UTC instant with milliseconds, got {raw!r}"
    )
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _snap_arn(region, snap):
    """The EBS snapshot notification's own ARN form, as in the EBS events documentation: account
    field empty, region in the account slot (`arn:aws:ec2::<region>:snapshot/<id>`)."""
    return f"arn:aws:ec2::{region}:snapshot/{snap}"


def _vol_arn_in_snap_event(region, vol):
    return f"arn:aws:ec2::{region}:volume/{vol}"


def _snapshots_for(envs, arn):
    return [e for e in envs if arn in e.get("resources", [])]


def _snap_state(ec2, snap):
    try:
        snaps = ec2.describe_snapshots(SnapshotIds=[snap])["Snapshots"]
    except ClientError as exc:
        if _code(exc) == "InvalidSnapshot.NotFound":
            return ("__gone__", None)
        raise
    return (snaps[0]["State"], snaps[0].get("StateMessage")) if snaps else ("__gone__", None)


def _delete_snapshot(ec2, snap):
    try:
        ec2.delete_snapshot(SnapshotId=snap)
    except ClientError as exc:
        if _code(exc) != "InvalidSnapshot.NotFound":
            raise


def _vol_state(ec2, vol):
    try:
        vols = ec2.describe_volumes(VolumeIds=[vol])["Volumes"]
    except ClientError as exc:
        if _code(exc) == "InvalidVolume.NotFound":
            return "__gone__"
        raise
    return vols[0]["State"] if vols else "__gone__"


def _delete_volume(ec2, vol):
    if _vol_state(ec2, vol) != "__gone__":
        ec2.delete_volume(VolumeId=vol)


def _source_volume(ctx, ec2, name):
    az = _zones_offering(ec2, _INSTANCE_TYPE)[0]
    vol = ec2.create_volume(AvailabilityZone=az, Size=1, VolumeType="gp3", TagSpecifications=[
        {"ResourceType": "volume", "Tags": _tags_for(name)}])["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, vol))
    _poll(lambda: _vol_state(ec2, vol), lambda s: s == "available",
          timeout_s=_budget_s(ctx, 300.0), ctx=ctx, interval_s=1.0, what=f"volume {vol} reaching 'available'")
    return vol


def _snapshot(ctx, ec2, vol, name):
    snap = ec2.create_snapshot(VolumeId=vol, Description="sim2real events-ec2-lifecycle",
                               TagSpecifications=[{"ResourceType": "snapshot",
                                                   "Tags": _tags_for(name)}])["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ec2, snap))
    return snap



_DRAIN_TIMEOUT_S = 600.0
_CLOCK_SLACK_S = 300
_ISO_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidInstanceID.NotFound")


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, *, timeout_s, interval_s, what, ctx=None):
    """Bounded poll that raises on timeout rather than returning its last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
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


def _collect(sqs, url, into, done, *, what, timeout_s=_DRAIN_TIMEOUT_S, ctx=None):
    deadline = time.monotonic() + timeout_s
    while not done(into) and time.monotonic() < deadline:
        wait = int(max(1, min(10, deadline - time.monotonic())))
        into.extend(_drain(sqs, url, wait=wait))
    if not done(into) and ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    assert done(into), (
        f"{what}: not delivered within {timeout_s:.0f}s. Received "
        f"{[(e.get('detail-type'), e.get('time'), e.get('detail')) for e in into]!r}. A target "
        f"that never emits its own events fails exactly here"
    )


def _prove_pipeline(ctx, events, sqs, account, name):
    """Positive control on a separate rule: EventBridge -> SQS delivers in this account.
    PutEvents is used only here, never for the event under test."""
    source = "sim2real.control"
    nonce = ctx.unique_name("nonce-")
    url = _wire(ctx, events, sqs, account, name + "-ctl",
                {"source": [source], "detail": {"nonce": [nonce]}})

    def attempt():
        resp = events.put_events(Entries=[{"Source": source, "DetailType": "sim2real control",
                                           "Detail": json.dumps({"nonce": nonce})}])
        assert resp["FailedEntryCount"] == 0, f"control PutEvents failed: {resp!r}"
        return [e for e in _drain(sqs, url) if e.get("detail", {}).get("nonce") == nonce]

    got = _poll(attempt, bool, timeout_s=_budget_s(ctx, 240.0), ctx=ctx, interval_s=2.0,
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
