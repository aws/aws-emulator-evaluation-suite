"""read-only-management-events-reach-a-rule-only-in-the-all-management-events-state."""

# An EventBridge rule in the "ENABLED" state receives only WRITE CloudTrail management events;
# receiving READ-ONLY ones requires the state "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" (AWS
# Compute Blog, "Introducing support for read-only management events in Amazon EventBridge"). A trail
# that is logging management events is required for any "AWS API Call via CloudTrail" event to be
# delivered (CloudTrail User Guide, "CloudTrail integration with Amazon EventBridge").
# sqs:GetQueueAttributes is a DATA event, which a trail with default event selectors never logs, so
# the read leg uses sqs:ListMessageMoveTasks, an SQS management event. It needs a queue that is a
# valid dead-letter-queue redrive target, hence the throwaway source queue with a RedrivePolicy naming
# the subject queue. The write/read classification is asserted through the delivered record's own
# `readOnly` member. The delivered envelope is {"source": "aws.sqs", "detail-type": "AWS API Call via
# CloudTrail", "detail": <the CloudTrail record>}.
# The CloudTrail-to-EventBridge fan-out can take longer than 900 s for the first event in an account
# while GetTrailStatus reports healthy delivery, and is near-real-time once live: the write leg gets
# 900 s and, once it is observed, the read leg 180 s. The read call is issued before the write call,
# so once the write event arrives the pipeline has passed the read's instant, and the absence leg
# holds 1x the measured positive latency. CloudTrail keeps writing for minutes after StopLogging, so
# the bucket drain retries and raises on a deadline miss.

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "read-only-management-events-reach-a-rule-only-in-the-all-management-events-state"
GROUP = "eventing"
SERVICES = ["cloudtrail", "events", "sqs"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# The rule state under test, and the whole point of the check.
_ALL_MANAGEMENT_STATE = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
_WRITE_ONLY_STATE = "ENABLED"

_DELIVERY_BUDGET_S = 900.0  # the WRITE leg's budget, which pays the cold-start allowance.
_WARM_DELIVERY_BUDGET_S = 180.0  # the READ leg's budget: reached only after the write leg has
# already proven the channel live, so it does not need to pay a second cold-start allowance.
_HOLD_CAP_S = 240.0
_CLEANUP_BUDGET_S = 240.0
_POLL_INTERVAL_S = 10.0


def _create_log_bucket(ctx, account_id):
    s3 = ctx.client("s3")
    name = ctx.unique_name("simparity-ct-evt-")
    kw = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's own default region; passing a LocationConstraint for it is
        # itself a 400 (InvalidLocationConstraint), so the literal here names the API's special
        # case, not a pinned target region.
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_policy(
        Bucket=name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{name}",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{name}/AWSLogs/{account_id}/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            }
        ),
    )
    return name


def _drain_and_delete_bucket(s3, bucket):
    """RAISES on a deadline miss so a leak is visible rather than silent."""
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        keys = []
        token = None
        while True:
            kw = {"Bucket": bucket, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            page = s3.list_objects_v2(**kw)
            keys.extend(o["Key"] for o in page.get("Contents", []))
            token = page.get("NextContinuationToken")
            if not token:
                break
        for i in range(0, len(keys), 1000):
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys[i : i + 1000]]}
            )
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
            raise AssertionError(
                f"bucket {bucket} still not empty after {_CLEANUP_BUDGET_S:.0f}s; this check is "
                "LEAKING a bucket -- report the name"
            )
        time.sleep(10.0)


def _create_queue(ctx, label):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"simparity-ct-{label}-")
    url = sqs.create_queue(
        QueueName=name, tags={"sim2real": CHECK, "simparity-role": label}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_quietly(sqs, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _delete_queue_quietly(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if "NonExistentQueue" not in str(exc.response.get("Error", {}).get("Code", "")):
            raise


def _allow_events_to_sqs(ctx, queue_url, queue_arn, rule_arns):
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": arn}},
                        }
                        for arn in rule_arns
                    ],
                }
            )
        },
    )


def _put_rule(ctx, pattern, state, queue_arn):
    events = ctx.client("events")
    name = ctx.unique_name("simparity-ct-rule-")
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State=state,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, Force=True))
    events.put_targets(Rule=name, Targets=[{"Id": "target1", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=name, Ids=["target1"], Force=True))
    return name, arn


def _drain(ctx, queue_url):
    """Every message currently visible on the queue, as parsed envelopes. Deletes each message it
    receives -- an earlier real-AWS run found a "stray" ListMessageMoveTasks envelope in leg 3 that
    was actually the leg-2 positive-leg's OWN message reappearing after its VisibilityTimeout lapsed,
    because nothing had ever deleted it. Left undeleted, any once-seen message can resurface every
    60s for the rest of the run and be mistaken for a fresh delivery in a LATER absence assertion."""
    sqs = ctx.client("sqs")
    out = []
    for _ in range(20):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=60
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            return out
        for m in msgs:
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _matching(envelopes, event_name, needle):
    return [
        e
        for e in envelopes
        if (e.get("detail") or {}).get("eventName") == event_name
        and needle in json.dumps(e.get("detail") or {})
    ]


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A read-only management event reaches an EventBridge rule only when the rule asks for all
    CloudTrail management events; a write event reaches both rules, and both go quiet once the
    trail stops logging."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    sqs = ctx.client("sqs")
    ct = ctx.client("cloudtrail")

    bucket = _create_log_bucket(ctx, account_id)
    trail_name = ctx.unique_name("simparity-ct-evt-")
    trail_arn = ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )["TrailARN"]
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_arn))
    ct.start_logging(Name=trail_arn)
    ctx.on_cleanup(lambda: _stop_logging_quietly(ct, trail_arn))
    assert ct.get_trail_status(Name=trail_arn).get("IsLogging") is True, (
        "the trail must be logging before either call is made, because the EventBridge channel "
        "requires one (H2): expected True, actual "
        f"{ct.get_trail_status(Name=trail_arn).get('IsLogging')!r}"
    )

    # The subject queue -- the one the two management calls are made against.
    subject_url, subject_arn = _create_queue(ctx, "subject")
    wide_url, wide_arn = _create_queue(ctx, "widesink")
    narrow_url, narrow_arn = _create_queue(ctx, "narrowsink")

    # ListMessageMoveTasks only means anything as a control-plane READ when its SourceArn names a
    # queue that is an actual redrive DLQ target; this throwaway queue exists only to make the
    # subject queue one. No message move is ever started -- the call under test is the LIST, not a
    # move -- so this queue is never otherwise touched.
    moveq_url, _moveq_arn = _create_queue(ctx, "moveresrc")
    sqs.set_queue_attributes(
        QueueUrl=moveq_url,
        Attributes={
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": subject_arn, "maxReceiveCount": "5"}
            )
        },
    )

    pattern = {
        "source": ["aws.sqs"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["sqs.amazonaws.com"],
            "eventName": ["TagQueue", "ListMessageMoveTasks"],
        },
    }
    wide_rule, wide_rule_arn = _put_rule(ctx, pattern, _ALL_MANAGEMENT_STATE, wide_arn)
    narrow_rule, narrow_rule_arn = _put_rule(ctx, pattern, _WRITE_ONLY_STATE, narrow_arn)
    _allow_events_to_sqs(ctx, wide_url, wide_arn, [wide_rule_arn])
    _allow_events_to_sqs(ctx, narrow_url, narrow_arn, [narrow_rule_arn])

    # The state must survive the round trip before anything else is claimed about it.
    described = ctx.client("events").describe_rule(Name=wide_rule)
    assert described["State"] == _ALL_MANAGEMENT_STATE, (
        "PutRule must store the all-management-events state verbatim: expected "
        f"{_ALL_MANAGEMENT_STATE!r}, actual {described['State']!r}"
    )
    narrow_described = ctx.client("events").describe_rule(Name=narrow_rule)
    assert narrow_described["State"] == _WRITE_ONLY_STATE, (
        f"the control rule's state: expected {_WRITE_ONLY_STATE!r}, actual "
        f"{narrow_described['State']!r}"
    )

    # ---- the two calls. READ FIRST, WRITE LAST, so the write is the structural barrier -------
    read_marker = ctx.unique_name("simparity-read-")
    move_tasks = sqs.list_message_move_tasks(SourceArn=subject_arn)
    # AWS omits the 'Results' key entirely (an empty {} body) when there are no tasks, rather than
    # returning Results: []. HTTPStatusCode is the actual success signal.
    assert move_tasks["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        "the read-only call must actually have succeeded: expected HTTPStatusCode 200, actual "
        f"{move_tasks!r}"
    )
    write_started = time.monotonic()
    sqs.tag_queue(QueueUrl=subject_url, Tags={"simparity-write-marker": read_marker})

    # ---- terminal read at the sinks -- a different service and operation from the mutations ---
    wide_seen, narrow_seen = [], []
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    while True:
        wide_seen += _drain(ctx, wide_url)
        narrow_seen += _drain(ctx, narrow_url)
        if _matching(wide_seen, "TagQueue", subject_arn) and _matching(
            narrow_seen, "TagQueue", subject_arn
        ):
            break
        if time.monotonic() >= deadline:
            status = ct.get_trail_status(Name=trail_arn)
            lookup = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "TagQueue"}],
                StartTime=status.get("StartLoggingTime"),
            )
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the WRITE management event (sqs:TagQueue on {subject_arn}) did "
                f"not reach both rules within {_DELIVERY_BUDGET_S:.0f}s; expected >=1 at each, "
                f"actual {len(_matching(wide_seen, 'TagQueue', subject_arn))} at the wide rule and "
                f"{len(_matching(narrow_seen, 'TagQueue', subject_arn))} at the narrow one. trail "
                f"diagnostics: IsLogging={status.get('IsLogging')!r} "
                f"LatestDeliveryError={status.get('LatestDeliveryError')!r} "
                f"LatestDeliveryTime={status.get('LatestDeliveryTime')!r} "
                f"LatestNotificationError={status.get('LatestNotificationError')!r} "
                f"StartLoggingTime={status.get('StartLoggingTime')!r} -- DIAGNOSTIC "
                f"lookup_events(EventName=TagQueue) found {len(lookup.get('Events', []))} event(s) "
                f"in CloudTrail's OWN history: {json.dumps(lookup.get('Events', []), default=str)[:600]!r}"
            )
        time.sleep(_POLL_INTERVAL_S)
    measured_latency_s = time.monotonic() - write_started

    # Envelope fidelity, on the write event, at BOTH rules.
    for label, seen, rule_state in (
        ("wide", wide_seen, _ALL_MANAGEMENT_STATE),
        ("narrow", narrow_seen, _WRITE_ONLY_STATE),
    ):
        env = _matching(seen, "TagQueue", subject_arn)[0]
        assert env.get("source") == "aws.sqs", (
            f"[{label}/{rule_state}] envelope source: expected 'aws.sqs', actual "
            f"{env.get('source')!r} (H4)"
        )
        assert env.get("detail-type") == "AWS API Call via CloudTrail", (
            f"[{label}] envelope detail-type: expected 'AWS API Call via CloudTrail', actual "
            f"{env.get('detail-type')!r} (H4)"
        )
        detail = env.get("detail") or {}
        assert detail.get("eventSource") == "sqs.amazonaws.com", (
            f"[{label}] detail.eventSource: expected 'sqs.amazonaws.com', actual "
            f"{detail.get('eventSource')!r}"
        )
        assert detail.get("readOnly") is False, (
            f"[{label}] TagQueue is a WRITE, so detail.readOnly must be False: actual "
            f"{detail.get('readOnly')!r} (H3 -- readOnly tracks the OPERATION, not the outcome)"
        )
        assert detail.get("eventCategory") == "Management", (
            f"[{label}] detail.eventCategory: expected 'Management', actual "
            f"{detail.get('eventCategory')!r}"
        )
        assert detail.get("recipientAccountId") == account_id, (
            f"[{label}] detail.recipientAccountId: expected {account_id!r}, actual "
            f"{detail.get('recipientAccountId')!r}"
        )
        assert read_marker in json.dumps(detail.get("requestParameters") or {}), (
            f"[{label}] the write's requestParameters must carry the tag value that was sent: "
            f"expected {read_marker!r} inside "
            f"{json.dumps(detail.get('requestParameters') or {})[:200]!r}, actual absent"
        )

    # ---- the positive leg the whole check is for: the READ event at the WIDE rule -----------------
    # The write leg above already proved the channel live, so this only needs the smaller WARM
    # budget -- not a second cold-start allowance.
    deadline = time.monotonic() + _WARM_DELIVERY_BUDGET_S
    while True:
        wide_seen += _drain(ctx, wide_url)
        if _matching(wide_seen, "ListMessageMoveTasks", subject_arn):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: a rule in state {_ALL_MANAGEMENT_STATE} must receive READ-ONLY "
                f"management events, and sqs:ListMessageMoveTasks on {subject_arn} never arrived "
                f"within {_WARM_DELIVERY_BUDGET_S:.0f}s of the channel being proven live; expected "
                f">=1, actual 0 of {len(wide_seen)} envelopes seen at that rule"
            )
        time.sleep(_POLL_INTERVAL_S)
    read_env = _matching(wide_seen, "ListMessageMoveTasks", subject_arn)[0]
    read_detail = read_env.get("detail") or {}
    assert read_detail.get("readOnly") is True, (
        "ListMessageMoveTasks is a READ, so detail.readOnly must be True -- this is the member that "
        f"makes the two rules' populations different: expected True, actual "
        f"{read_detail.get('readOnly')!r} (H3)"
    )
    assert read_detail.get("eventCategory") == "Management", (
        "a read-only management event is still a MANAGEMENT event: expected 'Management', actual "
        f"{read_detail.get('eventCategory')!r}"
    )
    assert not read_detail.get("errorCode"), (
        "the read succeeded, so its record must carry no errorCode: expected empty/None, actual "
        f"{read_detail.get('errorCode')!r}"
    )

    # ---- the negative leg: the read event must NOT be at the narrow rule -------------------------
    # Barrier is structural (the read was issued BEFORE the write, and the write has arrived at this
    # very rule), plus a calibrated hold of 1x the measured latency.
    hold_s = min(measured_latency_s, _HOLD_CAP_S)
    hold_deadline = time.monotonic() + hold_s
    strays = _matching(narrow_seen, "ListMessageMoveTasks", subject_arn)
    while not strays and time.monotonic() < hold_deadline:
        time.sleep(min(_POLL_INTERVAL_S, max(hold_deadline - time.monotonic(), 0.0)))
        narrow_seen += _drain(ctx, narrow_url)
        strays = _matching(narrow_seen, "ListMessageMoveTasks", subject_arn)
    assert strays == [], (
        f"a rule in state {_WRITE_ONLY_STATE} must NOT receive read-only management events: "
        f"expected 0 ListMessageMoveTasks envelopes naming {subject_arn}, actual {len(strays)}. The "
        f"write event reached this same rule in {measured_latency_s:.0f}s and a further "
        f"{hold_s:.0f}s was held, so the channel is demonstrably live. A target that ignores the "
        "rule State beyond enabled/disabled fails exactly here."
    )
    # A second independent observable for the same absence, so the leg is not one receive's word.
    depth = ctx.client("sqs").get_queue_attributes(
        QueueUrl=narrow_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", (
        "after draining, the write-only rule's sink must be empty rather than holding an "
        f"undelivered read event: expected '0', actual {depth!r}"
    )

    # ---- leg 3: with the trail stopped, the channel must go quiet ---------------------------
    ct.stop_logging(Name=trail_arn)
    assert ct.get_trail_status(Name=trail_arn).get("IsLogging") is False, (
        "StopLogging must be in effect before the third leg: expected False, actual "
        f"{ct.get_trail_status(Name=trail_arn).get('IsLogging')!r}"
    )
    _drain(ctx, wide_url)
    quiet_started = time.monotonic()
    sqs.list_message_move_tasks(SourceArn=subject_arn)
    # Hold 1x the latency the channel demonstrated while it WAS logging -- a calibrated window using
    # a value measured in this same run on this same wiring.
    quiet_deadline = quiet_started + min(measured_latency_s, _HOLD_CAP_S)
    late: list[dict] = []
    while not late and time.monotonic() < quiet_deadline:
        time.sleep(min(_POLL_INTERVAL_S, max(quiet_deadline - time.monotonic(), 0.0)))
        after = _drain(ctx, wide_url)
        late += [
            e
            for e in after
            if (e.get("detail") or {}).get("eventName") == "ListMessageMoveTasks"
            and subject_arn in json.dumps(e.get("detail") or {})
        ]
    assert late == [], (
        "with no trail logging management events, the EventBridge CloudTrail channel must deliver "
        f"nothing: expected 0 envelopes, actual {len(late)} after "
        f"{time.monotonic() - quiet_started:.0f}s. A target that synthesises these events without a "
        "trail fails exactly here (H2)."
    )


def _stop_logging_quietly(ct, trail_arn):
    try:
        ct.stop_logging(Name=trail_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
