"""xsvc-elbv2-1-delete-target-group-rule-receives-nothing-from-create."""

# AWS behaviour this check depends on:
#   M1  A trail is required: with none, CloudTrail-pattern rules never match. The first event
#       after a fresh trail's StartLogging can be lost, so an unrelated control proves the channel
#       live first.
#   M2  Once the control lands, elbv2 events arrive within seconds, so each elbv2 leg gets
#       _WARM_DELIVERY_BUDGET_S and only the control gate gets _COLD_DELIVERY_BUDGET_S. Control
#       emissions repeat every _REEMIT_S, because an event issued while the hop warms is dropped.
#   M3  Envelope: source "aws.elasticloadbalancing", detail-type "AWS API Call via CloudTrail",
#       detail.eventSource "elasticloadbalancing.amazonaws.com", detail.awsRegion = the call's
#       region, detail.requestParameters echoes the request in camelCase.
#   M4  A rejected duplicate CreateTargetGroup is delivered with detail.errorCode
#       "DuplicateTargetGroupNameException", while the API caller gets "DuplicateTargetGroupName".
#   M6  A landed SQS control does not prove the elasticloadbalancing stream live, so every elbv2 leg
#       re-emits its subject call every _REEMIT_S within its warm budget; any one arriving counts.

from __future__ import annotations

import datetime
import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-elbv2-1-delete-target-group-rule-receives-nothing-from-create"
GROUP = "eventing"
SERVICES = ["elbv2", "events", "sqs"]

_DETAIL_TYPE = "AWS API Call via CloudTrail"
_ELB_SOURCE = "aws.elasticloadbalancing"
_ELB_EVENT_SOURCE = "elasticloadbalancing.amazonaws.com"

_COLD_DELIVERY_BUDGET_S = 900.0  # M2: the control gate only, the first event through a new trail
_WARM_DELIVERY_BUDGET_S = 180.0  # M2: every elbv2 leg, run after the channel is proven live
_BUCKET_DRAIN_BUDGET_S = 40.0  # inside the 60 s cleanup chain
_REEMIT_S = 20.0  # M2: re-issue the control so a warm-up drop cannot starve the gate
_POLL_S = 3.0

# ===== helpers =====


def _error_code(fn):
    """The AWS error code fn() raised. RAISES if fn() succeeds, because an accepted call that real
    AWS rejects is the strongest possible signal and must not read like a naming difference."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


_GONE_CODES = frozenset({
    "TrailNotFoundException", "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist",
    "ResourceNotFoundException", "InvalidVpcID.NotFound", "TargetGroupNotFound",
})


def _quiet(fn):
    """Run one delete: an already-gone resource is fine; every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
            raise


def _drain_and_delete_bucket(s3, bucket):
    """CloudTrail can land one more log file after the trail goes, so empty-then-delete repeats until
    the deadline. Reports a leak on stderr rather than raising inside the cleanup chain."""
    deadline = time.monotonic() + _BUCKET_DRAIN_BUDGET_S
    while True:
        try:
            token = None
            while True:
                kw = {"Bucket": bucket, "MaxKeys": 1000}
                if token:
                    kw["ContinuationToken"] = token
                page = s3.list_objects_v2(**kw)
                keys = [o["Key"] for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys]}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
                token = page.get("NextContinuationToken")
                if not token:
                    break
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise RuntimeError(f"s3 bucket {bucket}: {code}") from exc
        time.sleep(5.0)


def _start_trail(ctx, account_id):
    """A single-region trail logging management events (M1)."""
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    bucket = ctx.unique_name("sim2real-xsvc-elbct-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's default; a LocationConstraint naming it is itself a 400.
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
                 "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}"},
                {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
                 "Action": "s3:PutObject",
                 "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                 "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
            ],
        }),
    )
    trail_arn = ct.create_trail(
        Name=ctx.unique_name("sim2real-xsvc-elbct-"),
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )["TrailARN"]
    ctx.on_cleanup(lambda: _quiet(lambda: ct.delete_trail(Name=trail_arn)))
    ct.start_logging(Name=trail_arn)
    logging = ct.get_trail_status(Name=trail_arn).get("IsLogging")
    assert logging is True, f"the trail must be logging before any event is made: actual {logging!r}"
    return trail_arn


def _queue(ctx, label, attributes=None):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-xsvc-elb-{label}-"),
        Attributes=attributes or {},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _quiet(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _allow_rule(ctx, queue_url, queue_arn, rule_arn):
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }],
        })},
    )


def _rule(ctx, pattern, targets):
    """A rule on the default bus. Cleanup is registered before the targets are put, and the
    remove_targets net is registered after them, so LIFO removes targets and then the rule."""
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-xsvc-elb-rule-")
    arn = events.put_rule(
        Name=name, EventPattern=json.dumps(pattern), State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _quiet(lambda: events.delete_rule(Name=name, Force=True)))
    resp = events.put_targets(Rule=name, Targets=targets)
    ids = [t["Id"] for t in targets]
    ctx.on_cleanup(lambda: _quiet(lambda: events.remove_targets(Rule=name, Ids=ids, Force=True)))
    assert resp.get("FailedEntryCount") == 0, f"PutTargets rejected entries: {resp.get('FailedEntries')!r}"
    return name, arn


def _elb_pattern(*event_names):
    return {
        "source": [_ELB_SOURCE],
        "detail-type": [_DETAIL_TYPE],
        "detail": {"eventSource": [_ELB_EVENT_SOURCE], "eventName": list(event_names)},
    }


def _drain(ctx, queue_url, raw=False):
    """Every message visible now. Each one is deleted, so a message seen once cannot resurface after
    its visibility timeout and be mistaken for a fresh delivery."""
    sqs = ctx.client("sqs")
    out = []
    for _ in range(20):
        msgs = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
            VisibilityTimeout=60, MessageAttributeNames=["All"],
        ).get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            out.append(m if raw else json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _vpc(ctx):
    """A throwaway VPC, so no check depends on a default VPC. Instance target groups need one."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [
            {"Key": "sim2real", "Value": CHECK},
            {"Key": "Name", "Value": ctx.unique_name("sim2real-xsvc-elb-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _quiet(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    return vpc_id


def _create_tg(ctx, name, vpc_id, port=80):
    elb = ctx.client("elbv2")
    arn = elb.create_target_group(
        Name=name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType="instance",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TargetGroups"][0]["TargetGroupArn"]
    return arn


def _prove_channel_live(ctx, trail_arn):
    """The cold-channel gate. An UNRELATED control (sqs:TagQueue on a throwaway queue) goes through its
    own rule and queue, re-emitted every _REEMIT_S, until one lands. No elbv2 call is made before this
    returns. Returns the seconds the gate took."""
    sqs = ctx.client("sqs")
    subject_url, _ = _queue(ctx, "ctlsubj")
    sink_url, sink_arn = _queue(ctx, "ctlsink")
    _, rule_arn = _rule(
        ctx,
        {"source": ["aws.sqs"], "detail-type": [_DETAIL_TYPE],
         "detail": {"eventSource": ["sqs.amazonaws.com"], "eventName": ["TagQueue"]}},
        [{"Id": "control", "Arn": sink_arn}],
    )
    _allow_rule(ctx, sink_url, sink_arn, rule_arn)
    started = time.monotonic()
    deadline = started + _COLD_DELIVERY_BUDGET_S
    last_emit = None
    emitted = 0
    while True:
        now = time.monotonic()
        if last_emit is None or now - last_emit >= _REEMIT_S:
            emitted += 1
            sqs.tag_queue(QueueUrl=subject_url, Tags={"sim2real-control": str(emitted)})
            last_emit = now
        landed = [e for e in _drain(ctx, sink_url) if subject_url in json.dumps(e.get("detail") or {})]
        if landed:
            return time.monotonic() - started
        if now >= deadline:
            status = ctx.client("cloudtrail").get_trail_status(Name=trail_arn)
            raise AssertionError(
                "PRECONDITION (cold channel, not the elbv2 claim): the CloudTrail->EventBridge channel "
                f"never delivered the unrelated sqs:TagQueue control within {_COLD_DELIVERY_BUDGET_S:.0f}s "
                f"({emitted} emissions); IsLogging={status.get('IsLogging')!r} "
                f"LatestDeliveryError={status.get('LatestDeliveryError')!r}. No elbv2 assertion was made."
            )
        time.sleep(_POLL_S)


def _await(ctx, queue_url, predicate, what, seen, budget_s=_WARM_DELIVERY_BUDGET_S, raw=False,
           rule=None, reemit=None):
    """Poll queue_url, appending to seen, until predicate(seen) holds or the WARM budget runs out.
    reemit (M6) repeats the subject call every _REEMIT_S. On a miss the failure quotes the rule's own
    AWS/Events counters when a rule name is given."""
    deadline = time.monotonic() + budget_s
    last_emit = time.monotonic()
    while True:
        if reemit is not None and time.monotonic() - last_emit >= _REEMIT_S:
            reemit()
            last_emit = time.monotonic()
        seen += _drain(ctx, queue_url, raw=raw)
        if predicate(seen):
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what}: nothing matching arrived within {budget_s:.0f}s of a channel already proven "
                f"live; received {len(seen)} other message(s): {json.dumps(seen, default=str)[:600]!r}; "
                f"rule counters {_rule_counters(ctx, rule) if rule else 'n/a'}"
            )
        time.sleep(_POLL_S)


def _rule_counters(ctx, rule_name):
    """DIAGNOSTIC only, quoted in a failure message and never asserted: the rule's own counters for
    the last 30 minutes, which separate 'never matched' from 'matched but the invocation failed'."""
    cw = ctx.client("cloudwatch")
    end = datetime.datetime.now(datetime.timezone.utc)
    out = {}
    for metric in ("MatchedEvents", "Invocations", "FailedInvocations", "InvocationsSentToDlq"):
        points = cw.get_metric_statistics(
            Namespace="AWS/Events", MetricName=metric,
            Dimensions=[{"Name": "RuleName", "Value": rule_name}],
            StartTime=end - datetime.timedelta(minutes=30), EndTime=end, Period=1800, Statistics=["Sum"],
        )["Datapoints"]
        out[metric] = points[0]["Sum"] if points else 0
    return out


def _named(envelopes, event_name, tg_name):
    return [
        e for e in envelopes
        if (e.get("detail") or {}).get("eventName") == event_name
        and ((e.get("detail") or {}).get("requestParameters") or {}).get("name") == tg_name
    ]


@tags(
    "axis:negative-delivery",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A DeleteTargetGroup rule receives nothing while only creates happen (AWS matches eventName
    exactly), though a CreateTargetGroup rule on the same bus receives both creates. A later
    DeleteTargetGroup then reaches that same queue, proving it was reachable all along.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    trail_arn = _start_trail(ctx, account_id)
    vpc_id = _vpc(ctx)

    create_url, create_arn = _queue(ctx, "posctl")
    delete_url, delete_arn = _queue(ctx, "delete")
    _, create_rule = _rule(ctx, _elb_pattern("CreateTargetGroup"), [{"Id": "sink", "Arn": create_arn}])
    _, delete_rule = _rule(ctx, _elb_pattern("DeleteTargetGroup"), [{"Id": "sink", "Arn": delete_arn}])
    _allow_rule(ctx, create_url, create_arn, create_rule)
    _allow_rule(ctx, delete_url, delete_arn, delete_rule)
    _prove_channel_live(ctx, trail_arn)

    elb = ctx.client("elbv2")
    tg_name = ctx.unique_name("sim2real-xsvc-tg-")
    tg_arn = _create_tg(ctx, tg_name, vpc_id)
    ctx.on_cleanup(lambda: _quiet(lambda: elb.delete_target_group(TargetGroupArn=tg_arn)))

    good = _await(ctx, create_url, lambda s: len(_named(s, "CreateTargetGroup", tg_name)) >= 1,
                  f"positive control: first CreateTargetGroup for {tg_name}", [],
                  reemit=lambda: _create_tg(ctx, tg_name, vpc_id))
    # A second, later create must also reach the control before the delete queue is checked.
    assert _create_tg(ctx, tg_name, vpc_id) == tg_arn, "the identical re-create must be idempotent"
    good = _await(ctx, create_url, lambda s: len(_named(s, "CreateTargetGroup", tg_name)) >= 2,
                  f"positive control: second CreateTargetGroup for {tg_name}", good,
                  reemit=lambda: _create_tg(ctx, tg_name, vpc_id))

    strays = _drain(ctx, delete_url)
    assert strays == [], (
        "a rule matching only eventName DeleteTargetGroup must receive nothing while only "
        f"CreateTargetGroup happens: actual {len(strays)} message(s), first "
        f"{json.dumps(strays[:1], default=str)[:400]!r}. The create rule delivered "
        f"{len(_named(good, 'CreateTargetGroup', tg_name))} creates on the same channel meanwhile."
    )
    depth = ctx.client("sqs").get_queue_attributes(
        QueueUrl=delete_url, AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
    )["Attributes"]
    assert (depth["ApproximateNumberOfMessages"], depth["ApproximateNumberOfMessagesNotVisible"]) == ("0", "0"), (
        f"the delete rule's queue must hold nothing at all: actual {depth!r}"
    )

    # Repair: supply the one missing thing. The same queue must now receive it.
    elb.delete_target_group(TargetGroupArn=tg_arn)
    got = _await(ctx, delete_url,
                 lambda s: [e for e in s if (e.get("detail") or {}).get("eventName") == "DeleteTargetGroup"
                            and ((e["detail"].get("requestParameters") or {}).get("targetGroupArn")) == tg_arn],
                 f"repair leg: DeleteTargetGroup for {tg_arn}", [],
                 reemit=lambda: _quiet(lambda: elb.delete_target_group(TargetGroupArn=tg_arn)))
    names = sorted({(e.get("detail") or {}).get("eventName") for e in got})
    assert names == ["DeleteTargetGroup"], f"the delete rule must only ever receive DeleteTargetGroup: actual {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
