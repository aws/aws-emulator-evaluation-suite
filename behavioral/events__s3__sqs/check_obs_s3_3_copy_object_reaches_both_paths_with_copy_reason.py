"""obs-s3-3-copy-object-reaches-both-paths-with-copy-reason."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-s3-3-copy-object-reaches-both-paths-with-copy-reason"
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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject reaches both notification paths as a copy (ObjectCreated:Copy and
    detail.reason CopyObject) with the destination's ETag and size, while the source PutObject
    is ObjectCreated:Put and reason PutObject."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ev = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    partition = s3.meta.partition

    bucket = _bucket(ctx, s3)
    curl, carn = _queue(ctx, sqs)
    _allow(sqs, curl, carn, "s3.amazonaws.com", f"arn:{partition}:s3:::{bucket}", account)
    eurl, _ = _rule_to_queue(ctx, ev, sqs, {
        "source": ["aws.s3"], "detail-type": ["Object Created"],
        "detail": {"bucket": {"name": [bucket]}}}, account)
    _wire_bucket(s3, bucket, [{"QueueArn": carn, "Events": ["s3:ObjectCreated:*"]}])
    classic, bridge = _Inbox(sqs, curl, "classic"), _Inbox(sqs, eurl, "eventbridge")

    def _fire(i: int) -> str:
        k = f"warm-{i}"
        s3.put_object(Bucket=bucket, Key=k, Body=b"sim2real-warm")
        return k

    _warm_up(_fire, [(classic, lambda k: _classic(k, "ObjectCreated:Put")),
                     (bridge, lambda k: _bridge(k, "Object Created"))])

    body = b"sim2real-copy-source-bytes"
    src_key = ctx.unique_name("src-")
    dst_key = ctx.unique_name("dst-")
    put = s3.put_object(Bucket=bucket, Key=src_key, Body=body)
    put_req = put["ResponseMetadata"]["RequestId"]
    src_c = _await(classic, _classic(src_key, "ObjectCreated:Put"), "classic Put for source")[0]
    src_e = _await(bridge, _bridge(src_key, "Object Created"), "EventBridge source creation")[0]
    assert src_e["detail"]["reason"] == "PutObject", (
        f"the source was created by PutObject; reason was {src_e['detail'].get('reason')!r}")
    assert src_c["responseElements"]["x-amz-request-id"] == put_req, (
        f"classic Put names request {src_c['responseElements']['x-amz-request-id']!r}, "
        f"expected {put_req!r}")

    cp = s3.copy_object(Bucket=bucket, Key=dst_key, CopySource={"Bucket": bucket, "Key": src_key})
    cp_req = cp["ResponseMetadata"]["RequestId"]
    dst_etag = cp["CopyObjectResult"]["ETag"].strip('"')
    head_dst = s3.head_object(Bucket=bucket, Key=dst_key)
    assert head_dst["ContentLength"] == len(body), f"copy is {head_dst['ContentLength']} bytes"

    crec = _await(classic, _classic(dst_key), "classic notification for the copy")[0]
    eenv = _await(bridge, _bridge(dst_key, "Object Created"), "EventBridge copy creation")[0]
    assert crec["eventName"] == "ObjectCreated:Copy", (
        f"CopyObject must notify as 'ObjectCreated:Copy', got {crec['eventName']!r}")
    assert crec["s3"]["object"]["eTag"] == dst_etag, (
        f"classic Copy eTag {crec['s3']['object'].get('eTag')!r} != CopyObject ETag {dst_etag!r}")
    assert crec["s3"]["object"]["size"] == len(body), (
        f"classic Copy size {crec['s3']['object'].get('size')!r} != {len(body)}")
    assert crec["responseElements"]["x-amz-request-id"] == cp_req, (
        f"classic Copy names request {crec['responseElements']['x-amz-request-id']!r}, "
        f"but CopyObject was request {cp_req!r}")
    assert eenv["detail"]["reason"] == "CopyObject", (
        f"an object created by CopyObject must carry reason 'CopyObject', got "
        f"{eenv['detail'].get('reason')!r}")
    assert eenv["detail"]["object"]["etag"] == dst_etag, (
        f"EventBridge copy etag {eenv['detail']['object'].get('etag')!r} != {dst_etag!r}")
    assert eenv["detail"]["object"]["size"] == len(body), (
        f"EventBridge copy size {eenv['detail']['object'].get('size')!r} != {len(body)}")
    assert eenv["detail"]["request-id"] == cp_req, (
        f"EventBridge copy names request {eenv['detail']['request-id']!r}, expected {cp_req!r}")

    # invariant: no path ever labelled the copy as a put, or the put as a copy
    cnames = {(r["s3"]["object"]["key"], r["eventName"])
              for r in _classic(src_key)(classic.seen) + _classic(dst_key)(classic.seen)}
    assert cnames == {(src_key, "ObjectCreated:Put"), (dst_key, "ObjectCreated:Copy")}, (
        f"classic path labelled the two creations {sorted(cnames)!r}")
    reasons = {(e["detail"]["object"]["key"], e["detail"].get("reason"))
               for e in _bridge(src_key)(bridge.seen) + _bridge(dst_key)(bridge.seen)}
    assert reasons == {(src_key, "PutObject"), (dst_key, "CopyObject")}, (
        f"EventBridge path labelled the two creations {sorted(reasons)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
