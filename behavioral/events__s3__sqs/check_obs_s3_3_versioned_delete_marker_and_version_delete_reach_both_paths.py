"""obs-s3-3-versioned-delete-marker-and-version-delete-reach-both-paths."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-s3-3-versioned-delete-marker-and-version-delete-reach-both-paths"
GROUP = 'eventing'
SERVICES = ['events', 's3', 'sqs']


_DELIVERY_BUDGET_S = 90.0
_NOTIFY_CONFIG_WAIT_S = 60.0


def _purge_bucket(s3, name: str) -> None:
    """Delete every version and delete marker, then the bucket. Never raises a teardown error."""
    for _ in range(3):
        doomed = []
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                doomed.append({"Key": v["Key"], "VersionId": v["VersionId"]})
        for i in range(0, len(doomed), 1000):
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": doomed[i:i + 1000], "Quiet": True}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        try:
            s3.delete_bucket(Bucket=name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "BucketNotEmpty":
                raise
    raise RuntimeError(f"s3 bucket {name} still not empty after 3 purge rounds")


def _bucket(ctx, s3, *, versioned: bool = False) -> str:
    name = ctx.unique_name("sim2real-xsvc-s3ev-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _purge_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    if versioned:
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


def _queue(ctx, sqs) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-s3ev-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _allow(sqs, url: str, arn: str, principal: str, source_arn: str, account: str) -> None:
    """Admit exactly one producer: *principal* acting for *source_arn* in *account*."""
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "OneProducer", "Effect": "Allow",
            "Principal": {"Service": principal},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": source_arn},
                          "StringEquals": {"aws:SourceAccount": account}},
        }],
    })})


def _rule_to_queue(ctx, ev, sqs, pattern: dict, account: str) -> tuple[str, str]:
    """A default-bus rule with *pattern*, targeting a fresh queue only that rule may write."""
    url, qarn = _queue(ctx, sqs)
    rule = ctx.unique_name("sim2real-xsvc-s3ev-")
    rule_arn = ev.put_rule(Name=rule, EventPattern=json.dumps(pattern), State="ENABLED",
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["RuleArn"]
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))
    _allow(sqs, url, qarn, "events.amazonaws.com", rule_arn, account)
    resp = ev.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": qarn}])
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["q"]))
    assert resp["FailedEntryCount"] == 0, (
        f"put_targets on {rule!r} reported failures: {resp.get('FailedEntries')!r}")
    return url, rule


def _wire_bucket(s3, bucket: str, queue_configs: list[dict]) -> None:
    """Classic QueueConfigurations AND EventBridge delivery on the SAME bucket, in one call.
    S3 validates each queue by sending s3:TestEvent, which fails with InvalidArgument until the
    queue policy has propagated; that is the only code retried."""
    cfg = {"QueueConfigurations": queue_configs, "EventBridgeConfiguration": {}}
    deadline = time.monotonic() + _NOTIFY_CONFIG_WAIT_S
    while True:
        try:
            s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration=cfg)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidArgument" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    got = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in got, (
        f"bucket {bucket!r} must be EventBridge-enabled; GetBucketNotificationConfiguration "
        f"returned {got!r}")
    want = sorted((q["QueueArn"], tuple(sorted(q["Events"]))) for q in queue_configs)
    have = sorted((q["QueueArn"], tuple(sorted(q["Events"])))
                  for q in got.get("QueueConfigurations", []))
    assert have == want, f"queue configurations read back as {have!r}, expected {want!r}"


class _Inbox:
    """Everything one queue has delivered so far. Messages are deleted as they are read, and
    every body is kept, so a later assertion can inspect strays as well as hits."""

    def __init__(self, sqs, url: str, label: str):
        self.sqs, self.url, self.label, self.seen = sqs, url, label, []

    def pump(self, wait: int = 2) -> None:
        msgs = self.sqs.receive_message(QueueUrl=self.url, MaxNumberOfMessages=10,
                                        WaitTimeSeconds=wait).get("Messages", [])
        if msgs:
            self.sqs.delete_message_batch(QueueUrl=self.url, Entries=[
                {"Id": f"m{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
        self.seen += [json.loads(m["Body"]) for m in msgs]

    def soak(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.pump()

    def digest(self) -> list[str]:
        out = []
        for b in self.seen:
            if "Records" in b:
                out += [f"{r.get('eventName')}:{r['s3']['object']['key']}" for r in b["Records"]]
            elif "detail-type" in b:
                out.append(f"{b['detail-type']}:{b.get('detail', {}).get('object', {}).get('key')}")
            else:
                out.append(str(b.get("Event", b))[:60])
        return out


def _classic(key: str, name: str | None = None):
    """Classic S3 notification records for *key* (optionally only eventName == *name*)."""
    return lambda seen: [r for b in seen for r in b.get("Records", [])
                         if r["s3"]["object"]["key"] == key
                         and (name is None or r.get("eventName") == name)]


def _bridge(key: str, detail_type: str | None = None):
    """EventBridge envelopes from aws.s3 for *key* (optionally only one detail-type)."""
    return lambda seen: [b for b in seen if b.get("source") == "aws.s3"
                         and b.get("detail", {}).get("object", {}).get("key") == key
                         and (detail_type is None or b.get("detail-type") == detail_type)]


def _await(inbox: _Inbox, select, what: str, budget_s: float = _DELIVERY_BUDGET_S) -> list:
    deadline = time.monotonic() + budget_s
    while True:
        hits = select(inbox.seen)
        if hits:
            return hits
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what}: nothing arrived on the {inbox.label} queue within {budget_s:.0f}s; "
                f"it received {inbox.digest()!r}")
        inbox.pump()


_WARM_BUDGET_S = 150.0
_WARM_ROUND_WAIT_S = 20.0


def _warm_up(fire, probes) -> None:
    """New rules and fresh queue policies are eventually consistent: an event emitted before a
    rule is effective is never matched, and one denied by a not-yet-propagated policy waits in
    EventBridge's retry backoff. So the routes count as live only once TWO CONSECUTIVE rounds
    of `fire(i)` (each on its own warm-up key, never the key under test) reach EVERY probe
    within _WARM_ROUND_WAIT_S. *probes* is [(inbox, key -> selector)]."""
    deadline = time.monotonic() + _WARM_BUDGET_S
    streak, i = 0, 0
    while streak < 2:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"routes never delivered two consecutive warm-up rounds within {_WARM_BUDGET_S:.0f}s; "
                f"inboxes held {[(ib.label, ib.digest()) for ib, _ in probes]!r}")
        key = fire(i)
        i += 1
        round_deadline = time.monotonic() + _WARM_ROUND_WAIT_S
        pending = list(probes)
        while pending and time.monotonic() < round_deadline:
            pending = [(ib, sel) for ib, sel in pending if not sel(key)(ib.seen)]
            for ib, _ in pending:
                ib.pump(wait=1)
        streak = streak + 1 if not pending else 0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a versioned bucket a versionless DeleteObject reaches both paths as a delete-marker
    creation naming the marker's version id, and deleting a specific version as a permanent
    delete naming that version."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ev = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    partition = s3.meta.partition

    bucket = _bucket(ctx, s3, versioned=True)
    status = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    assert status == "Enabled", f"bucket versioning reads back {status!r}"
    curl, carn = _queue(ctx, sqs)
    _allow(sqs, curl, carn, "s3.amazonaws.com", f"arn:{partition}:s3:::{bucket}", account)
    eurl, _ = _rule_to_queue(ctx, ev, sqs, {
        "source": ["aws.s3"], "detail": {"bucket": {"name": [bucket]}}}, account)
    _wire_bucket(s3, bucket, [{"QueueArn": carn,
                               "Events": ["s3:ObjectCreated:Put", "s3:ObjectRemoved:*"]}])
    classic, bridge = _Inbox(sqs, curl, "classic"), _Inbox(sqs, eurl, "eventbridge")

    def _fire(i: int) -> str:
        k = f"warm-{i}"
        s3.put_object(Bucket=bucket, Key=k, Body=b"sim2real-warm")
        return k

    _warm_up(_fire, [(classic, lambda k: _classic(k, "ObjectCreated:Put")),
                     (bridge, lambda k: _bridge(k, "Object Created"))])

    key = ctx.unique_name("versioned-")
    put = s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-v1")
    v1 = put["VersionId"]
    c_put = _await(classic, _classic(key, "ObjectCreated:Put"), "classic Put warm-up")[0]
    e_put = _await(bridge, _bridge(key, "Object Created"), "EventBridge creation warm-up")[0]
    assert c_put["s3"]["object"]["versionId"] == v1, (
        f"classic Put versionId {c_put['s3']['object'].get('versionId')!r} != {v1!r}")
    assert e_put["detail"]["object"]["version-id"] == v1, (
        f"EventBridge creation version-id {e_put['detail']['object'].get('version-id')!r} != {v1!r}")

    # --- versionless delete: a delete marker is created ---------------------------------------
    d1 = s3.delete_object(Bucket=bucket, Key=key)
    assert d1.get("DeleteMarker") is True, f"versionless delete returned {d1!r}"
    marker = d1["VersionId"]
    c_dm = _await(classic, _classic(key, "ObjectRemoved:DeleteMarkerCreated"),
                  "classic ObjectRemoved:DeleteMarkerCreated")[0]
    e_del = _await(bridge, _bridge(key, "Object Deleted"), "EventBridge 'Object Deleted'")[0]
    assert c_dm["s3"]["object"]["versionId"] == marker, (
        f"classic DeleteMarkerCreated names version {c_dm['s3']['object'].get('versionId')!r}, "
        f"but the marker S3 returned is {marker!r}")
    assert e_del["detail"]["reason"] == "DeleteObject", (
        f"'Object Deleted' reason {e_del['detail'].get('reason')!r}, expected 'DeleteObject'")
    assert e_del["detail"]["deletion-type"] == "Delete Marker Created", (
        f"a versionless delete on a versioned bucket must be 'Delete Marker Created', got "
        f"{e_del['detail'].get('deletion-type')!r}")
    assert e_del["detail"]["object"]["version-id"] == marker, (
        f"'Object Deleted' names version {e_del['detail']['object'].get('version-id')!r}, "
        f"expected the marker {marker!r}")
    stack = s3.list_object_versions(Bucket=bucket, Prefix=key)
    assert [v["VersionId"] for v in stack.get("Versions", [])] == [v1], (
        f"the data version must survive a delete marker; versions are {stack.get('Versions')!r}")
    assert [m["VersionId"] for m in stack.get("DeleteMarkers", [])] == [marker], (
        f"delete markers are {stack.get('DeleteMarkers')!r}, expected [{marker!r}]")

    # --- version-specific delete: permanent ---------------------------------------------------
    d2 = s3.delete_object(Bucket=bucket, Key=key, VersionId=v1)
    assert d2.get("VersionId") == v1 and not d2.get("DeleteMarker"), (
        f"deleting version {v1!r} returned {d2!r}")
    c_perm = _await(classic, _classic(key, "ObjectRemoved:Delete"), "classic ObjectRemoved:Delete")[0]
    e_perm = _await(bridge, lambda seen: [e for e in _bridge(key, "Object Deleted")(seen)
                                          if e["detail"].get("deletion-type") != "Delete Marker Created"],
                    "EventBridge permanent 'Object Deleted'")[0]
    assert c_perm["s3"]["object"]["versionId"] == v1, (
        f"classic ObjectRemoved:Delete names version {c_perm['s3']['object'].get('versionId')!r}, "
        f"expected {v1!r}")
    assert e_perm["detail"]["deletion-type"] == "Permanently Deleted", (
        f"deleting a specific version must be 'Permanently Deleted', got "
        f"{e_perm['detail'].get('deletion-type')!r}")
    assert e_perm["detail"]["reason"] == "DeleteObject", (
        f"permanent delete reason {e_perm['detail'].get('reason')!r}, expected 'DeleteObject'")
    assert e_perm["detail"]["object"]["version-id"] == v1, (
        f"permanent 'Object Deleted' names version "
        f"{e_perm['detail']['object'].get('version-id')!r}, expected {v1!r}")

    # invariant: exactly the three transitions, each named once per vocabulary
    cnames = {(r["eventName"], r["s3"]["object"].get("versionId")) for r in _classic(key)(classic.seen)}
    assert cnames == {("ObjectCreated:Put", v1), ("ObjectRemoved:DeleteMarkerCreated", marker),
                      ("ObjectRemoved:Delete", v1)}, f"classic path delivered {sorted(cnames)!r}"
    etypes = {(e["detail-type"], e["detail"].get("deletion-type"), e["detail"]["object"].get("version-id"))
              for e in _bridge(key)(bridge.seen)}
    assert etypes == {("Object Created", None, v1),
                      ("Object Deleted", "Delete Marker Created", marker),
                      ("Object Deleted", "Permanently Deleted", v1)}, (
        f"EventBridge path delivered {sorted(etypes, key=str)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
