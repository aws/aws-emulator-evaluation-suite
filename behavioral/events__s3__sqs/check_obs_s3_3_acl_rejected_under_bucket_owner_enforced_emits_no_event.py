"""obs-s3-3-acl-rejected-under-bucket-owner-enforced-emits-no-event."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-s3-3-acl-rejected-under-bucket-owner-enforced-emits-no-event"
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
    """New rules and queue policies are eventually consistent, so routes count as live only once
    two consecutive rounds of `fire(i)` (own warm-up keys) reach every probe within
    _WARM_ROUND_WAIT_S. *probes* is [(inbox, key -> selector)]."""
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


_ABSENCE_FLOOR_BUDGET_S = 20.0
_ABSENCE_CEILING_BUDGET_S = 60.0


def _absence_window(latency_s: float) -> float:
    """3x the slowest MEASURED positive delivery in this run, floored and capped."""
    return min(max(_ABSENCE_FLOOR_BUDGET_S, 3.0 * latency_s), _ABSENCE_CEILING_BUDGET_S)


_ACL_REFUSAL = "The bucket does not allow ACLs"


def _error(fn) -> tuple[str, int, str]:
    """(error code, HTTP status, message) of a call that must fail; a success raises."""
    try:
        resp = fn()
    except ClientError as e:
        return (e.response["Error"]["Code"], e.response["ResponseMetadata"]["HTTPStatusCode"],
                e.response["Error"].get("Message"))
    raise AssertionError(f"the call was expected to be rejected but succeeded: {resp!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:e2e", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Under BucketOwnerEnforced, PutObjectAcl is rejected, the ACL is unchanged and neither the
    classic nor the EventBridge path carries an ACL event for it; after BucketOwnerPreferred the
    same call succeeds and both paths deliver an event naming the successful request id.
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ev = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    partition = s3.meta.partition

    bucket = _bucket(ctx, s3)
    own = s3.get_bucket_ownership_controls(Bucket=bucket)["OwnershipControls"]["Rules"]
    assert own == [{"ObjectOwnership": "BucketOwnerEnforced"}], (
        f"a new bucket must default to BucketOwnerEnforced; ownership reads {own!r}")
    curl, carn = _queue(ctx, sqs)
    _allow(sqs, curl, carn, "s3.amazonaws.com", f"arn:{partition}:s3:::{bucket}", account)
    eurl, _ = _rule_to_queue(ctx, ev, sqs, {
        "source": ["aws.s3"], "detail-type": ["Object ACL Updated", "Object Tags Added"],
        "detail": {"bucket": {"name": [bucket]}}}, account)
    _wire_bucket(s3, bucket, [{"QueueArn": carn,
                               "Events": ["s3:ObjectAcl:Put", "s3:ObjectTagging:Put"]}])
    classic, bridge = _Inbox(sqs, curl, "classic"), _Inbox(sqs, eurl, "eventbridge")

    def _fire(i: int) -> str:
        k = f"warm-{i}"
        s3.put_object(Bucket=bucket, Key=k, Body=b"sim2real-warm")
        s3.put_object_tagging(Bucket=bucket, Key=k, Tagging={"TagSet": [{"Key": "w", "Value": "1"}]})
        return k

    _warm_up(_fire, [(classic, lambda k: _classic(k, "ObjectTagging:Put")),
                     (bridge, lambda k: _bridge(k, "Object Tags Added"))])

    key = ctx.unique_name("acl-")
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-acl-rejected")
    owner = s3.get_object_acl(Bucket=bucket, Key=key)["Owner"]["ID"]
    policy = {"Owner": {"ID": owner}, "Grants": [
        {"Grantee": {"Type": "CanonicalUser", "ID": owner}, "Permission": "FULL_CONTROL"},
        {"Grantee": {"Type": "CanonicalUser", "ID": owner}, "Permission": "READ_ACP"}]}

    # --- the rejected call ----------------------------------------------------------------
    rejected_ids: list[str] = []

    def _rejected_put():
        try:
            return s3.put_object_acl(Bucket=bucket, Key=key, AccessControlPolicy=policy)
        except ClientError as e:
            rejected_ids.append(e.response["ResponseMetadata"]["RequestId"])
            raise

    code, status, message = _error(_rejected_put)
    assert (code, status, message) == ("AccessControlListNotSupported", 400, _ACL_REFUSAL), (
        f"PutObjectAcl under BucketOwnerEnforced returned {code!r}/{status} {message!r}, expected "
        f"AccessControlListNotSupported/400 {_ACL_REFUSAL!r}")
    grants = {(g["Grantee"].get("ID"), g["Permission"])
              for g in s3.get_object_acl(Bucket=bucket, Key=key)["Grants"]}
    assert grants == {(owner, "FULL_CONTROL")}, f"a rejected PutObjectAcl changed the ACL to {grants!r}"

    # --- barrier: a later event on the same routes arrives --------------------------------
    t0 = time.monotonic()
    s3.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": [{"Key": "k", "Value": "v"}]})
    _await(classic, _classic(key, "ObjectTagging:Put"), "classic ObjectTagging:Put (barrier)")
    _await(bridge, _bridge(key, "Object Tags Added"), "EventBridge 'Object Tags Added' (barrier)")
    window = _absence_window(time.monotonic() - t0)
    classic.soak(window / 2)
    bridge.soak(window / 2)
    c_acl = _classic(key, "ObjectAcl:Put")(classic.seen)
    e_acl = _bridge(key, "Object ACL Updated")(bridge.seen)
    assert c_acl == [] and e_acl == [], (
        f"a REJECTED PutObjectAcl was delivered: classic {len(c_acl)} ObjectAcl:Put, EventBridge "
        f"{len(e_acl)} 'Object ACL Updated' over {window:.0f}s past the barrier")

    # --- closure: repair the one thing, and the same queues receive the ACL event ---------
    s3.put_bucket_ownership_controls(Bucket=bucket, OwnershipControls={
        "Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]})
    # The ownership change is the only thing repaired; its propagation is retried on exactly the
    # code it cures, and every refused attempt's request id joins the rejected set.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            ok_req = s3.put_object_acl(Bucket=bucket, Key=key,
                                       AccessControlPolicy=policy)["ResponseMetadata"]["RequestId"]
            break
        except ClientError as e:
            if (e.response["Error"]["Code"] != "AccessControlListNotSupported"
                    or time.monotonic() >= deadline):
                raise
            rejected_ids.append(e.response["ResponseMetadata"]["RequestId"])
            time.sleep(3)
    grants = {(g["Grantee"].get("ID"), g["Permission"])
              for g in s3.get_object_acl(Bucket=bucket, Key=key)["Grants"]}
    assert grants == {(owner, "FULL_CONTROL"), (owner, "READ_ACP")}, f"repaired ACL reads {grants!r}"
    _await(classic, _classic(key, "ObjectAcl:Put"), "classic ObjectAcl:Put after repair (closure)")
    _await(bridge, _bridge(key, "Object ACL Updated"), "EventBridge ACL event after repair (closure)")
    classic.soak(2)
    bridge.soak(2)
    c_ids = {r["responseElements"]["x-amz-request-id"] for r in _classic(key, "ObjectAcl:Put")(classic.seen)}
    e_ids = {e["detail"]["request-id"] for e in _bridge(key, "Object ACL Updated")(bridge.seen)}
    assert c_ids == {ok_req} and e_ids == {ok_req}, (
        f"every ACL event must name the successful request {ok_req!r} (the rejected one was "
        f"{rejected_ids!r}); classic named {sorted(c_ids)!r}, EventBridge named {sorted(e_ids)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
