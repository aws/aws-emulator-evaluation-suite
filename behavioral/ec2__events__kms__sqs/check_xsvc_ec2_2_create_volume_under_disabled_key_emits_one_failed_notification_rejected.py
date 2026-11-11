"""xsvc-ec2-2-create-volume-under-disabled-key-emits-one-failed-notification-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-ec2-2-create-volume-under-disabled-key-emits-one-failed-notification-rejected"
GROUP = "event-propagation"
SERVICES = ["ec2", "events", "kms", "sqs"]

_SOURCE = "aws.ec2"
_DETAIL_TYPE = "EBS Volume Notification"
_DELIVERY_BUDGET_S = 300.0
_POLL_S = 3.0


@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """CreateVolume under a disabled KMS key is accepted, then EventBridge delivers exactly one
    createVolume/failed notification naming the key and a deleteVolume/deleted withdrawal; an
    enabled key yields createVolume/available, as does the same request after EnableKey.
    """
    ec2 = ctx.client("ec2")
    kms = ctx.client("kms")
    sqs = ctx.client("sqs")
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-ebsfail-")

    key_a = _new_key(ctx, kms, name + "-a")
    key_b = _new_key(ctx, kms, name + "-b")
    zone = _zone(ctx, ec2)

    queue = _wire(ctx, events, sqs, account, name, {
        "source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})

    kms.disable_key(KeyId=key_a)
    state = kms.describe_key(KeyId=key_a)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"key A must be Disabled before CreateVolume, got {state!r}"

    # The break and its control, issued back to back onto the same rule.
    vol_b = _create_volume(ctx, ec2, zone, key_b, name)
    # CreateVolume under the disabled key is ACCEPTED synchronously (it mints a volume id); the
    # refusal is asynchronous and graded below on its terminal outcome.
    vol_a = _create_volume(ctx, ec2, zone, key_a, name)
    created_state = _created_state[vol_a]
    assert created_state == "creating", (
        f"CreateVolume under the disabled key must be ACCEPTED synchronously in state 'creating' "
        f"(the refusal is asynchronous); got {created_state!r}"
    )
    arn_a = f"arn:aws:ec2:{ctx.region}:{account}:volume/{vol_a}"
    arn_b = f"arn:aws:ec2:{ctx.region}:{account}:volume/{vol_b}"

    got: list = []
    _collect(sqs, queue, got, lambda g: (
        _of(g, arn_b, "createVolume") and _of(g, arn_a, "createVolume")
        and _of(g, arn_a, "deleteVolume")),
        what=f"createVolume for {vol_b} (control) and createVolume+deleteVolume for {vol_a}")
    # Barrier reached: drain further, so 'exactly one' is a statement about a settled queue.
    for _ in range(3):
        got.extend(_drain(sqs, queue, wait=5))

    failed = _distinct(_of(got, arn_a, "createVolume"))
    assert len(failed) == 1, (
        f"exactly ONE createVolume notification must exist for the disabled-key volume {vol_a}; "
        f"got {len(failed)} distinct events: {[e['detail'] for e in failed]!r}"
    )
    env = failed[0]
    _assert_envelope(ctx, account, env)
    d = env["detail"]
    assert d.get("result") == "failed", (
        f"detail.result for the disabled-key volume must be 'failed', got {d.get('result')!r}"
    )
    assert d.get("cause") == f"{key_a} is disabled.", (
        f"detail.cause must name the disabled key: expected {key_a + ' is disabled.'!r}, "
        f"got {d.get('cause')!r}"
    )
    assert env.get("resources") == [arn_a, key_a], (
        f"a failed createVolume must carry [volume arn, key arn] as resources: expected "
        f"{[arn_a, key_a]!r}, got {env.get('resources')!r}"
    )
    withdrawn = _distinct(_of(got, arn_a, "deleteVolume"))
    assert len(withdrawn) == 1 and withdrawn[0]["detail"].get("result") == "deleted", (
        f"EBS must withdraw the failed volume with one deleteVolume/deleted notification; got "
        f"{[e['detail'] for e in withdrawn]!r}"
    )
    assert withdrawn[0]["detail"].get("request-id") == d.get("request-id"), (
        f"the withdrawal must share the failed request's request-id: createVolume "
        f"{d.get('request-id')!r} vs deleteVolume {withdrawn[0]['detail'].get('request-id')!r}"
    )
    code, message = _error_code(lambda: ec2.describe_volumes(VolumeIds=[vol_a]),
                                what=f"DescribeVolumes on the withdrawn volume {vol_a}")
    assert code == "InvalidVolume.NotFound", (
        f"the failed volume must no longer exist: expected InvalidVolume.NotFound, got {code!r}"
    )
    expected = f"The volume '{vol_a}' does not exist."
    assert message == expected, (
        f"InvalidVolume.NotFound message: expected {expected!r}, got {message!r}"
    )

    # Positive control on the same rule and queue; its result is `available`, not `succeeded`.
    ok = _distinct(_of(got, arn_b, "createVolume"))
    assert len(ok) == 1, f"one createVolume event for control {vol_b}, got {ok!r}"
    _assert_envelope(ctx, account, ok[0])
    assert ok[0]["detail"].get("result") == "available", (
        f"the enabled-key control volume's createVolume result must be 'available', got "
        f"{ok[0]['detail']!r}"
    )
    assert ok[0]["detail"].get("cause") == "", (
        f"a successful createVolume carries an empty cause, got {ok[0]['detail'].get('cause')!r}"
    )
    assert ok[0].get("resources") == [arn_b], (
        f"a successful createVolume carries only the volume arn, got {ok[0].get('resources')!r}"
    )
    assert not _of(got, arn_b, "deleteVolume"), (
        f"the control volume must not be withdrawn: {[e['detail'] for e in got]!r}"
    )

    # Repair exactly one thing: re-enable key A; the identical request now succeeds.
    kms.enable_key(KeyId=key_a)
    state = kms.describe_key(KeyId=key_a)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"key A must be Enabled after EnableKey, got {state!r}"
    vol_a2 = _create_volume(ctx, ec2, zone, key_a, name)
    arn_a2 = f"arn:aws:ec2:{ctx.region}:{account}:volume/{vol_a2}"
    _collect(sqs, queue, got, lambda g: _of(g, arn_a2, "createVolume"),
             what=f"createVolume for the repaired-key volume {vol_a2}")
    rep = _distinct(_of(got, arn_a2, "createVolume"))
    assert [e["detail"].get("result") for e in rep] == ["available"], (
        f"after EnableKey the identical request must yield one createVolume/available, got "
        f"{[e['detail'] for e in rep]!r}"
    )
    desc = ec2.describe_volumes(VolumeIds=[vol_a2])["Volumes"][0]
    assert (desc["Encrypted"], desc.get("KmsKeyId")) == (True, key_a), (
        f"the repaired volume must be encrypted under key A, got "
        f"{(desc['Encrypted'], desc.get('KmsKeyId'))!r}"
    )


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error_code(fn, *, what):
    """The exact (code, message) of a call that must fail; an ACCEPTED call raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} was ACCEPTED; real AWS refuses it")


def _new_key(ctx, kms, desc):
    arn = kms.create_key(Description=desc, Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:200]}]
                         )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _zone(ctx, ec2):
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, f"region {ctx.region!r} reports no available availability zone"
    return zones[0]


def _create_volume(ctx, ec2, zone, key_arn, name):
    """A 1 GiB gp3 volume under ``key_arn``, tagged in the same call, delete registered at once."""
    vol = ec2.create_volume(
        AvailabilityZone=zone, Size=1, VolumeType="gp3", Encrypted=True, KmsKeyId=key_arn,
        TagSpecifications=[{"ResourceType": "volume", "Tags": [
            {"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]}])
    vid = vol["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, vid))
    _created_state[vid] = vol["State"]
    return vid


#: CreateVolume's synchronous State, per volume id.
_created_state: dict = {}


def _delete_volume(ec2, vid):
    deadline = time.monotonic() + 300
    while True:
        try:
            ec2.delete_volume(VolumeId=vid)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return
            if _code(exc) != "IncorrectState" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _wire(ctx, events, sqs, account, name, pattern):
    """One SQS queue, a default-bus rule, and the rule->queue target. Returns the queue URL."""
    url = sqs.create_queue(QueueName=name[:80], tags={"sim2real": "1"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    rule = name[:64]
    rule_arn = events.put_rule(Name=rule, EventPattern=json.dumps(pattern), State="ENABLED",
                               Tags=[{"Key": "sim2real", "Value": "1"}])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, Force=True))
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
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    while not done(into) and time.monotonic() < deadline:
        into.extend(_drain(sqs, url))
    assert done(into), (
        f"{what}: not delivered within {_DELIVERY_BUDGET_S}s. Received "
        f"{[(e.get('resources'), e.get('detail')) for e in into]!r}"
    )


def _of(envs, vol_arn, event):
    return [e for e in envs if vol_arn in (e.get("resources") or [])
            and (e.get("detail") or {}).get("event") == event]


def _distinct(envs):
    """At-least-once delivery may repeat an event under the SAME id; count distinct ids."""
    by_id: dict = {}
    for e in envs:
        by_id.setdefault(e["id"], e)
    return list(by_id.values())


def _assert_envelope(ctx, account, env):
    assert env.get("source") == _SOURCE, f"expected source {_SOURCE!r}, got {env.get('source')!r}"
    assert env.get("detail-type") == _DETAIL_TYPE, (
        f"expected detail-type {_DETAIL_TYPE!r}, got {env.get('detail-type')!r}"
    )
    assert env.get("account") == account, f"expected account {account!r}, got {env.get('account')!r}"
    assert env.get("region") == ctx.region, (
        f"expected region {ctx.region!r}, got {env.get('region')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
