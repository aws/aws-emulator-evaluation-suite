"""xsvc-cloudfront-1-read-only-calls-not-delivered-to-enabled-rule."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-1-read-only-calls-not-delivered-to-enabled-rule"
GROUP = "negative-delivery"
SERVICES = ["cloudfront", "events"]

# CloudFront is a global service: CloudTrail records its API calls in us-east-1 and the
# "AWS API Call via CloudTrail" events derived from them reach only us-east-1's default bus, so the
# trail, rules and sinks are pinned there. This literal names CloudFront's control-plane/CloudTrail
# region; it is not a pinned target region.
_EVENT_REGION = "us-east-1"
# Each check stands up its own trail, so it first passes a readiness barrier (_READY_BUDGET_S, never
# asserted as a latency) and only then gives each routing leg the warm budget. Body worst case:
# ~60s setup + 600 + 3x180 + ~200s distribution retire, under the 1800s check budget.
_READY_BUDGET_S = 600.0
_DELIVERY_BUDGET_S = 180.0
_HOLD_FLOOR_S = 30.0
_HOLD_CAP_S = 120.0
_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"  # AWS-managed cache policy


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CloudFront reads are not delivered to a plain ENABLED rule naming them while a TagResource
    write on the same rule is; a near-miss detail-type rule gets nothing; an
    ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS rule does receive the same reads.
    """
    cf = ctx.client("cloudfront", region=_EVENT_REGION)
    ref = ctx.unique_name("sim2real-xsvc-cfro-")
    dist = _subject_distribution(ctx, cf, ref)
    dist_id, dist_arn = dist["Id"], dist["ARN"]

    names = ["GetDistribution", "ListDistributions", "TagResource"]
    pattern = {
        "source": ["aws.cloudfront"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {"eventName": names},
    }
    near_miss = {
        "source": ["aws.cloudfront"],
        "detail-type": ["AWS Service Event via CloudTrail"],
        "detail": {"eventName": names},
    }
    narrow_url, narrow_rules = _sink(ctx, "narrow", [(pattern, "ENABLED")])
    miss_url, _ = _sink(ctx, "nearmiss", [(near_miss, "ENABLED")])
    wide_url, wide_rules = _sink(
        ctx, "wide", [(pattern, "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS")]
    )
    events = ctx.client("events", region=_EVENT_REGION)
    states = (
        events.describe_rule(Name=narrow_rules[0])["State"],
        events.describe_rule(Name=wide_rules[0])["State"],
    )
    assert states == ("ENABLED", "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"), (
        f"rule states must round-trip verbatim: expected ('ENABLED', "
        f"'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS'), actual {states!r}"
    )

    ct, trail_arn = _start_trail(ctx)  # created LAST so LIFO teardown removes it FIRST
    seen: dict[str, list] = {}
    _await_sinks_live(ctx, [narrow_url, miss_url, wide_url], seen)
    narrow, miss, wide = (list(seen[u]) for u in (narrow_url, miss_url, wide_url))

    # READS FIRST, WRITE LAST: once the write has reached a sink the pipeline has passed the
    # reads' instant, which is the structural half of the absence barrier.
    get_rid = cf.get_distribution(Id=dist_id)["ResponseMetadata"]["RequestId"]
    list_rid = cf.list_distributions(MaxItems="1")["ResponseMetadata"]["RequestId"]
    fired = time.monotonic()
    tag_rid = cf.tag_resource(
        Resource=dist_arn, Tags={"Items": [{"Key": "sim2real-probe", "Value": ref}]}
    )["ResponseMetadata"]["RequestId"]

    def _rid(rid):
        return lambda e: (e.get("detail") or {}).get("requestID") == rid

    # Positive control on the SAME rule and sink: the write is delivered.
    tag_env = _await_envelope(ctx, narrow_url, narrow, _rid(tag_rid), "TagResource (narrow)")
    latency_s = time.monotonic() - fired
    assert tag_env.get("detail-type") == "AWS API Call via CloudTrail", (
        f"positive control detail-type: expected 'AWS API Call via CloudTrail', actual "
        f"{tag_env.get('detail-type')!r}"
    )
    assert (tag_env.get("detail") or {}).get("readOnly") is False, (
        f"TagResource is a write: expected readOnly False, actual "
        f"{(tag_env.get('detail') or {}).get('readOnly')!r}"
    )

    # Repair leg: the very same reads DO reach the all-management-events rule.
    get_env = _await_envelope(ctx, wide_url, wide, _rid(get_rid), "GetDistribution (wide)")
    _await_envelope(ctx, wide_url, wide, _rid(list_rid), "ListDistributions (wide)")
    _await_envelope(ctx, wide_url, wide, _rid(tag_rid), "TagResource (wide)")
    get_detail = get_env.get("detail") or {}
    assert get_detail.get("eventName") == "GetDistribution", (
        f"wide-rule read record eventName: expected 'GetDistribution', actual "
        f"{get_detail.get('eventName')!r}"
    )
    assert get_detail.get("readOnly") is True, (
        f"GetDistribution is a read: expected readOnly True, actual {get_detail.get('readOnly')!r}"
    )

    # Negative legs, held one measured latency past the barrier.
    hold_s = min(max(latency_s, _HOLD_FLOOR_S), _HOLD_CAP_S)
    sqs = ctx.client("sqs", region=_EVENT_REGION)
    hold_deadline = time.monotonic() + hold_s
    reads = {get_rid, list_rid}
    while time.monotonic() < hold_deadline:
        narrow.extend(_drain(sqs, narrow_url))
        miss.extend(_drain(sqs, miss_url))
        time.sleep(_POLL_INTERVAL_S)
    narrow.extend(_drain(sqs, narrow_url))
    miss.extend(_drain(sqs, miss_url))
    leaked = [
        (e.get("detail") or {}).get("eventName")
        for e in narrow
        if (e.get("detail") or {}).get("requestID") in reads
    ]
    assert leaked == [], (
        "a rule in state ENABLED must NOT receive read-only management events: expected [], "
        f"actual {leaked!r}; the write reached this same sink {latency_s:.0f}s after the call and "
        f"the same reads reached the all-management-events rule, then {hold_s:.0f}s was held"
    )
    ours = reads | {tag_rid}
    mismatched = [
        (e.get("detail-type"), (e.get("detail") or {}).get("eventName"))
        for e in miss
        if (e.get("detail") or {}).get("requestID") in ours
    ]
    assert mismatched == [], (
        "a rule on detail-type 'AWS Service Event via CloudTrail' must not match API-call "
        f"records: expected [], actual {mismatched!r}"
    )

    _delete_trail_quietly(ct, trail_arn)
    _retire_distribution(cf, dist_id, 900.0)


_POLL_INTERVAL_S = 5.0
_BUCKET_DRAIN_BUDGET_S = 30.0
_BARRIER_PATTERN = {
    "source": ["aws.cloudfront"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {"eventName": ["UpdateOriginAccessControl"]},
}
_BARRIER_KEY = "sim2real-barrier-"


def _start_trail(ctx):
    """A single-region us-east-1 trail recording global-service (CloudFront) management events,
    logging before any trigger fires. Returns (cloudtrail client, trail ARN)."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3", region=_EVENT_REGION)
    ct = ctx.client("cloudtrail", region=_EVENT_REGION)
    bucket = ctx.unique_name("sim2real-xsvc-cfct-")
    # us-east-1 is CreateBucket's default; a LocationConstraint naming it is itself a 400.
    s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            }
        ),
    )
    trail_arn = ct.create_trail(
        Name=ctx.unique_name("sim2real-xsvc-cfct-"),
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=True,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )["TrailARN"]
    ctx.on_cleanup(lambda: _delete_trail_quietly(ct, trail_arn))
    ct.start_logging(Name=trail_arn)
    logging = ct.get_trail_status(Name=trail_arn).get("IsLogging")
    assert logging is True, (
        f"the trail must be logging before any trigger fires: expected True, actual {logging!r}"
    )
    return ct, trail_arn


def _delete_trail_quietly(ct, trail_arn):
    try:
        ct.delete_trail(Name=trail_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
            raise


def _drain_and_delete_bucket(s3, bucket):
    """CloudTrail can land a log file after the trail is gone, so drain-then-delete in a bounded
    loop and say so on stderr if it never converges."""
    deadline = time.monotonic() + _BUCKET_DRAIN_BUDGET_S
    while True:
        keys = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys.extend(o["Key"] for o in page.get("Contents", []))
        for i in range(0, len(keys), 1000):
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys[i : i + 1000]]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty":
                raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"trail bucket {bucket} not empty after drain")
        time.sleep(5.0)


def _sink(ctx, label, patterns):
    """An SQS sink behind one rule per (pattern, state) PLUS a barrier rule on CloudFront
    UpdateOriginAccessControl that targets the SAME sink, with one queue policy admitting all of
    them. Returns (url, subject rule names)."""
    sqs = ctx.client("sqs", region=_EVENT_REGION)
    events = ctx.client("events", region=_EVENT_REGION)
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-xsvc-cf-{label}-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    names, arns = [], []
    for pattern, state in list(patterns) + [(_BARRIER_PATTERN, "ENABLED")]:
        name = ctx.unique_name("sim2real-xsvc-cf-rule-")
        arns.append(
            events.put_rule(
                Name=name,
                EventPattern=json.dumps(pattern),
                State=state,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )["RuleArn"]
        )
        ctx.on_cleanup(lambda n=name: events.delete_rule(Name=n, Force=True))
        events.put_targets(Rule=name, Targets=[{"Id": "sink", "Arn": arn}])
        ctx.on_cleanup(lambda n=name: events.remove_targets(Rule=n, Ids=["sink"], Force=True))
        names.append(name)
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": a}},
                        }
                        for a in arns
                    ],
                }
            )
        },
    )
    return url, names[:-1]


def _drain(sqs, url):
    """Every message currently visible, parsed and DELETED, so a once-seen message cannot
    resurface after its visibility timeout and be mistaken for a fresh delivery."""
    out = []
    for _ in range(20):
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=60
        ).get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _is_barrier(env):
    detail = env.get("detail") or {}
    return detail.get("eventName") == "UpdateOriginAccessControl" and _BARRIER_KEY in json.dumps(
        detail
    )


def _await_sinks_live(ctx, urls, seen):
    """Readiness barrier, not a latency assertion: update a barrier OAC every 30s until its record
    reaches EVERY sink, so a later absence is a routing verdict. A fresh trail's first delivery can
    take minutes and earlier records are never delivered, so the budget is generous."""
    cf = ctx.client("cloudfront", region=_EVENT_REGION)
    sqs = ctx.client("sqs", region=_EVENT_REGION)
    oac_id = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name(_BARRIER_KEY),
            "Description": "sim2real readiness barrier",
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_barrier_oac(cf, oac_id))
    pending = set(urls)
    started = time.monotonic()
    last_fire = -1e9
    markers: set[str] = set()
    while pending:
        if time.monotonic() - last_fire >= 30.0:
            got = cf.get_origin_access_control(Id=oac_id)
            cfg = got["OriginAccessControl"]["OriginAccessControlConfig"]
            marker = ctx.unique_name(_BARRIER_KEY)
            markers.add(marker)
            cfg["Description"] = marker
            cf.update_origin_access_control(
                Id=oac_id, IfMatch=got["ETag"], OriginAccessControlConfig=cfg
            )
            last_fire = time.monotonic()
        time.sleep(_POLL_INTERVAL_S)
        for u in list(pending):
            got_envs = _drain(sqs, u)
            seen.setdefault(u, []).extend(got_envs)
            if any(_is_barrier(e) and any(m in json.dumps(e["detail"]) for m in markers)
                   for e in got_envs):
                pending.discard(u)
        if pending and time.monotonic() - started >= _READY_BUDGET_S:
            raise AssertionError(
                f"CHANNEL NOT LIVE (not a routing verdict): no CloudFront UpdateOriginAccessControl "
                f"record reached {len(pending)} sink(s) within {_READY_BUDGET_S:.0f}s of the trail "
                f"starting to log: {sorted(pending)!r}"
            )
    _delete_barrier_oac(cf, oac_id)
    return time.monotonic() - started


def _delete_barrier_oac(cf, oac_id):
    try:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
        cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchOriginAccessControl":
            raise


def _await_envelope(ctx, url, seen, predicate, what):
    sqs = ctx.client("sqs", region=_EVENT_REGION)
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    while True:
        seen.extend(_drain(sqs, url))
        hits = [e for e in seen if predicate(e)]
        if hits:
            return hits[0]
        if time.monotonic() >= deadline:
            names = [(e.get("detail") or {}).get("eventName") for e in seen]
            raise AssertionError(
                f"{what} did not arrive within {_DELIVERY_BUDGET_S:.0f}s of a channel proven "
                f"live; the sink saw {len(seen)} other envelope(s) naming {names!r}"
            )
        time.sleep(_POLL_INTERVAL_S)


def _subject_distribution(ctx, cf, ref):
    """A DISABLED distribution: it accepts CreateInvalidation/TagResource while InProgress, and
    needs no disable round-trip before DeleteDistribution."""
    cfg = {
        "CallerReference": ref,
        "Comment": "sim2real xsvc cloudfront__events check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": f"{ref}.s3.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_OPTIMIZED_POLICY_ID,
        },
    }
    dist = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": cfg,
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        }
    )["Distribution"]
    ctx.on_cleanup(lambda: _retire_distribution(cf, dist["Id"], 900.0))
    return dist


def _retire_distribution(cf, dist_id, budget_s):
    """Disable if needed, wait for Deployed, delete; raise if it is still not gone after budget_s.
    Called from the body and again as the cleanup net for the failure path."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            got = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
                return
            raise
        dist = got["Distribution"]
        if dist["DistributionConfig"]["Enabled"]:
            cfg = cf.get_distribution_config(Id=dist_id)
            body = cfg["DistributionConfig"]
            body["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=body, IfMatch=cfg["ETag"])
            continue
        if dist["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=got["ETag"])
            return
        if time.monotonic() >= deadline:
            message = (
                f"distribution {dist_id} still {dist['Status']} after {budget_s:.0f}s; it is "
                "disabled and tagged sim2real"
            )
            raise RuntimeError(message)
        time.sleep(2.0)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
