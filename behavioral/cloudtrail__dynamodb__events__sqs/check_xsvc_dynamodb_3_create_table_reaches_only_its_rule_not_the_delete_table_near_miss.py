"""xsvc-dynamodb-3-create-table-reaches-only-its-rule-not-the-delete-table-near-miss."""

# DynamoDB emits no native EventBridge events: the only path from a DynamoDB control-plane call to
# the default bus is CloudTrail's "AWS API Call via CloudTrail" management-event fan-out.

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-3-create-table-reaches-only-its-rule-not-the-delete-table-near-miss"
GROUP = "eventing"
SERVICES = ["cloudtrail", "dynamodb", "events", "sqs"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_DETAIL_TYPE = "AWS API Call via CloudTrail"
_EVENT_SOURCE = "dynamodb.amazonaws.com"

# A new trail's CloudTrail->EventBridge hop can take well over 15 minutes to warm up; only the
# control leg pays that, and every dynamodb leg runs after the channel is proven live.
_COLD_DELIVERY_BUDGET_S = 1800.0
_WARM_DELIVERY_BUDGET_S = 180.0
_ABSENCE_HOLD_S = 60.0  # draining kept up after a barrier, before an absence is asserted
_TABLE_ACTIVE_BUDGET_S = 180.0
_TEARDOWN_BUDGET_S = 120.0  # in-body bucket drain
_CLEANUP_BUCKET_BUDGET_S = 30.0  # the cleanup chain has a 60 s ceiling
_TABLE_TEARDOWN_WAIT_S = 120.0
_LONG_POLL_S = 5
_REEMIT_S = 120.0  # control writes are re-issued with a fresh marker while the channel warms

# ===== helpers =====


def _error_code(exc):
    return exc.response.get("Error", {}).get("Code")


def _create_trail_bucket(ctx, s3, account_id):
    name = ctx.unique_name("sim2real-xsvc-ctddb3-")
    kw = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's own default region; a LocationConstraint naming it is a 400,
        # so this literal names the API's special case, not a pinned target region.
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(
        lambda: _drain_and_delete_bucket(s3, name, _CLEANUP_BUCKET_BUDGET_S, raise_on_leak=True)
    )
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


def _drain_and_delete_bucket(s3, bucket, budget_s, *, raise_on_leak: bool = False):
    """Returns True once the bucket is gone. The bucket policy is removed first so CloudTrail can
    land no further log file; the empty-then-delete repeats until the deadline, then returns False
    for the registered cleanup to retry, or raises when ``raise_on_leak`` (that cleanup)."""
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if _error_code(exc) == "NoSuchBucket":
            return True
        raise
    deadline = time.monotonic() + budget_s
    while True:
        try:
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
            s3.delete_bucket(Bucket=bucket)
            return True
        except ClientError as exc:
            if _error_code(exc) == "NoSuchBucket":
                return True
            if _error_code(exc) != "BucketNotEmpty":
                raise
        if time.monotonic() >= deadline:
            msg = f"s3 bucket {bucket} still not empty after {budget_s:.0f}s"
            if raise_on_leak:
                raise RuntimeError(msg)
            return False
        time.sleep(3.0)


def _delete_trail_quietly(ct, trail_arn):
    try:
        ct.stop_logging(Name=trail_arn)
    except ClientError as exc:
        if _error_code(exc) != "TrailNotFoundException":
            raise
    try:
        ct.delete_trail(Name=trail_arn)
    except ClientError as exc:
        if _error_code(exc) != "TrailNotFoundException":
            raise


def _create_queue(ctx, sqs, label):
    name = ctx.unique_name(f"sim2real-xsvc-ctddb3-{label}-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_quietly(sqs, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _delete_queue_quietly(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if "NonExistentQueue" not in str(_error_code(exc)):
            raise


def _put_rule_to_queue(ctx, events, sqs, pattern, queue_url, queue_arn):
    name = ctx.unique_name("sim2real-xsvc-ctddb3-rule-")
    arn = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, Force=True))
    events.put_targets(Rule=name, Targets=[{"Id": "sink", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=name, Ids=["sink"], Force=True))
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "ThisRuleOnly",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": arn}},
                        }
                    ],
                }
            )
        },
    )
    return name


def _collect(sqs, url, sink, wait_s):
    """Long-poll once for up to wait_s, then drain whatever else is visible. Each item is the
    RAW body string; every message is deleted as it is read, so none can resurface after its
    visibility timeout and be mistaken for a fresh delivery in a later absence assertion."""
    wait = wait_s
    for _ in range(20):
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait, VisibilityTimeout=60
        ).get("Messages", [])
        if not msgs:
            return
        for m in msgs:
            sink.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        wait = 0


def _env(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return {}


def _detail(raw):
    return _env(raw).get("detail") or {}


def _named(raws, event_name):
    return [r for r in raws if _detail(r).get("eventName") == event_name]


def _for_table(raws, event_name, table_name):
    return [
        r
        for r in _named(raws, event_name)
        if (_detail(r).get("requestParameters") or {}).get("tableName") == table_name
    ]


def _tag_hits(raws, marker):
    return [
        r
        for r in _named(raws, "TagQueue")
        if marker in json.dumps(_detail(r).get("requestParameters") or {})
    ]


def _wait_table_active(ddb, table_name):
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if last == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(
        f"table {table_name!r} did not reach ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s; last "
        f"status {last!r}"
    )


def _delete_table_when_possible(ddb, table_name):
    """Delete the table, waiting out CREATING (DeleteTable on a CREATING table is
    ResourceInUseException). Idempotent on ResourceNotFoundException; raises when it cannot
    converge."""
    deadline = time.monotonic() + _TABLE_TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = _error_code(exc)
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"dynamodb table {table_name!r} could not be deleted: {code}"
                ) from exc
            return


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """DynamoDB's CreateTable, via CloudTrail, reaches the EventBridge rule naming it with this
    run's exact tableName, and never reaches a near-miss rule naming DeleteTable (or vice versa).

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    ddb = ctx.client("dynamodb")

    # ---- the trail -----------------------------------------------------------------------------
    bucket = _create_trail_bucket(ctx, s3, account_id)
    trail_name = ctx.unique_name("sim2real-xsvc-ctddb3-")
    trail_arn = None
    attempts = 0
    while trail_arn is None:
        attempts += 1
        try:
            trail_arn = ct.create_trail(
                Name=trail_name,
                S3BucketName=bucket,
                IsMultiRegionTrail=False,
                IncludeGlobalServiceEvents=False,
                TagsList=[{"Key": "sim2real", "Value": CHECK}],
            )["TrailARN"]
        except ClientError as exc:
            # The bucket policy is eventually consistent; this is the only code that means "not
            # yet", and it is retried rather than asserted.
            if _error_code(exc) != "InsufficientS3BucketPolicyException" or attempts >= 30:
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _delete_trail_quietly(ct, trail_arn))
    ct.put_event_selectors(
        TrailName=trail_arn,
        EventSelectors=[{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}],
    )
    ct.start_logging(Name=trail_arn)
    status = ct.get_trail_status(Name=trail_arn)
    assert status.get("IsLogging") is True, (
        f"the trail must be logging before any write is made (F1): actual {status!r}"
    )

    # ---- three rules, three sinks ---------------------------------------------------------------
    # The patterns are not narrowed to this run's table, so positives are filtered by tableName and
    # negatives are stated over eventName alone, which a concurrent run cannot make false.
    ctl_url, ctl_arn = _create_queue(ctx, sqs, "ctl")
    sub_url, sub_arn = _create_queue(ctx, sqs, "sub")
    near_url, near_arn = _create_queue(ctx, sqs, "near")
    _put_rule_to_queue(
        ctx,
        events,
        sqs,
        {
            "source": ["aws.sqs"],
            "detail-type": [_DETAIL_TYPE],
            "detail": {"eventSource": ["sqs.amazonaws.com"], "eventName": ["TagQueue"]},
        },
        ctl_url,
        ctl_arn,
    )
    subject_rule = _put_rule_to_queue(
        ctx,
        events,
        sqs,
        {
            "source": ["aws.dynamodb"],
            "detail-type": [_DETAIL_TYPE],
            "detail": {"eventSource": [_EVENT_SOURCE], "eventName": ["CreateTable"]},
        },
        sub_url,
        sub_arn,
    )
    near_rule = _put_rule_to_queue(
        ctx,
        events,
        sqs,
        {
            "source": ["aws.dynamodb"],
            "detail-type": [_DETAIL_TYPE],
            "detail": {"eventSource": [_EVENT_SOURCE], "eventName": ["DeleteTable"]},
        },
        near_url,
        near_arn,
    )

    at_ctl, at_sub, at_near = [], [], []

    # ---- leg 1: prove the channel live with an unrelated control write -------------------------
    markers = [ctx.unique_name("ctl-")]
    sqs.tag_queue(QueueUrl=ctl_url, Tags={"sim2real-marker": markers[-1]})
    started = time.monotonic()
    next_reemit = started + _REEMIT_S
    deadline = started + _COLD_DELIVERY_BUDGET_S

    def _control_hits():
        return [r for mk in markers for r in _tag_hits(at_ctl, mk)]

    while not _control_hits():
        if time.monotonic() >= deadline:
            st = ct.get_trail_status(Name=trail_arn)
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the CloudTrail->EventBridge channel never went live: none of "
                f"{len(markers)} sqs:TagQueue control writes (markers {markers!r}) reached the "
                f"control rule within {_COLD_DELIVERY_BUDGET_S:.0f}s; expected >=1, actual 0 of "
                f"{len(at_ctl)} messages seen. No dynamodb call was made. Trail: "
                f"IsLogging={st.get('IsLogging')!r} "
                f"LatestDeliveryError={st.get('LatestDeliveryError')!r} "
                f"LatestDeliveryTime={st.get('LatestDeliveryTime')!r}"
            )
        if time.monotonic() >= next_reemit:
            markers.append(ctx.unique_name("ctl-"))
            sqs.tag_queue(QueueUrl=ctl_url, Tags={"sim2real-marker": markers[-1]})
            next_reemit = time.monotonic() + _REEMIT_S
        _collect(sqs, ctl_url, at_ctl, _LONG_POLL_S)
    cold_s = time.monotonic() - started
    ctl_env = _env(_control_hits()[0])
    assert ctl_env.get("source") == "aws.sqs" and ctl_env.get("detail-type") == _DETAIL_TYPE, (
        f"control envelope: expected source 'aws.sqs' and detail-type {_DETAIL_TYPE!r}, actual "
        f"{ctl_env.get('source')!r} / {ctl_env.get('detail-type')!r}"
    )
    print(f"[timing] control leg: {len(markers)} marker(s), landed after {cold_s:.1f}s")

    # ---- leg 2: CreateTable --------------------------------------------------------------------
    table_name = ctx.unique_name("sim2real-xsvc-ctddb3-")
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, table_name))
    created = ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TableDescription"]
    assert created.get("TableName") == table_name, (
        f"CreateTable answered TableName {created.get('TableName')!r}, expected {table_name!r}"
    )
    _wait_table_active(ddb, table_name)

    create_started = time.monotonic()
    deadline = create_started + _WARM_DELIVERY_BUDGET_S
    while not _for_table(at_sub, "CreateTable", table_name):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the subject rule ({subject_rule}) never delivered "
                f"dynamodb:CreateTable for table {table_name!r} within "
                f"{_WARM_DELIVERY_BUDGET_S:.0f}s, although the same trail and bus delivered the "
                f"control TagQueue (channel proven live after {cold_s:.0f}s); expected 1, actual 0 "
                f"of {len(at_sub)} messages seen"
            )
        _collect(sqs, sub_url, at_sub, _LONG_POLL_S)
        _collect(sqs, near_url, at_near, 0)
    create_latency_s = time.monotonic() - create_started
    raw = _for_table(at_sub, "CreateTable", table_name)[0]
    env = _env(raw)
    detail = env.get("detail") or {}
    params = detail.get("requestParameters") or {}
    print(f"[timing] CreateTable delivered after {create_latency_s:.1f}s")

    assert env.get("source") == "aws.dynamodb", (
        f"source: expected 'aws.dynamodb', actual {env.get('source')!r}"
    )
    assert env.get("detail-type") == _DETAIL_TYPE, (
        f"detail-type: expected {_DETAIL_TYPE!r}, actual {env.get('detail-type')!r}"
    )
    assert detail.get("eventSource") == _EVENT_SOURCE, (
        f"detail.eventSource: expected {_EVENT_SOURCE!r}, actual {detail.get('eventSource')!r}"
    )
    assert detail.get("eventName") == "CreateTable", (
        f"detail.eventName: expected 'CreateTable', actual {detail.get('eventName')!r}"
    )
    assert env.get("account") == account_id and detail.get("recipientAccountId") == account_id, (
        f"envelope account and detail.recipientAccountId: expected {account_id!r}, actual "
        f"{env.get('account')!r} / {detail.get('recipientAccountId')!r}"
    )
    assert env.get("region") == ctx.region and detail.get("awsRegion") == ctx.region, (
        f"a regional dynamodb event stays in its region: expected {ctx.region!r}, actual "
        f"envelope region {env.get('region')!r}, detail.awsRegion {detail.get('awsRegion')!r}"
    )
    assert detail.get("readOnly") is False and detail.get("eventCategory") == "Management", (
        f"CreateTable is a write management event: expected readOnly False and eventCategory "
        f"'Management', actual {detail.get('readOnly')!r} / {detail.get('eventCategory')!r}"
    )
    assert params.get("tableName") == table_name, (
        f"detail.requestParameters.tableName: expected {table_name!r}, actual "
        f"{params.get('tableName')!r} (members present: {sorted(params)!r})"
    )

    # ---- leg 3: DeleteTable -- the near-miss rule's positive control ---------------------------
    # Issued only after the create was delivered, so its own delivery proves the near-miss wiring
    # was live while the create went past it.
    ddb.delete_table(TableName=table_name)
    deadline = time.monotonic() + _WARM_DELIVERY_BUDGET_S
    while not _for_table(at_near, "DeleteTable", table_name):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the near-miss rule ({near_rule}) never delivered "
                f"dynamodb:DeleteTable for table {table_name!r} within "
                f"{_WARM_DELIVERY_BUDGET_S:.0f}s, although the subject rule delivered the create "
                f"in {create_latency_s:.0f}s; expected 1, actual 0 of {len(at_near)} messages"
            )
        _collect(sqs, near_url, at_near, _LONG_POLL_S)
        _collect(sqs, sub_url, at_sub, 0)
    del_env = _env(_for_table(at_near, "DeleteTable", table_name)[0])
    assert del_env.get("source") == "aws.dynamodb" and del_env.get("detail-type") == (
        _DETAIL_TYPE
    ), (
        f"DeleteTable envelope: expected source 'aws.dynamodb' and detail-type {_DETAIL_TYPE!r}, "
        f"actual {del_env.get('source')!r} / {del_env.get('detail-type')!r}"
    )
    del_detail = del_env.get("detail") or {}
    del_params = del_detail.get("requestParameters") or {}
    assert del_params.get("tableName") == table_name, (
        f"the delete names the SAME table: expected tableName {table_name!r}, actual "
        f"{del_params.get('tableName')!r}"
    )

    # Both sinks keep draining a while longer before the absences are asserted.
    hold_until = time.monotonic() + _ABSENCE_HOLD_S
    while time.monotonic() < hold_until:
        _collect(sqs, near_url, at_near, _LONG_POLL_S)
        _collect(sqs, sub_url, at_sub, _LONG_POLL_S)
    near_creates = _named(at_near, "CreateTable")
    assert near_creates == [], (
        f"the near-miss rule ({near_rule}) matches eventName DeleteTable only, so its sink must "
        f"hold no CreateTable for any table: actual {len(near_creates)}, e.g. "
        f"{near_creates[:1]!r}. Its wiring was live: it delivered this run's DeleteTable, which "
        f"was issued only after the create had reached the subject rule"
    )
    near_other = [r for r in at_near if _detail(r).get("eventName") != "DeleteTable"]
    assert near_other == [], (
        f"the near-miss sink must hold nothing but DeleteTable: actual {len(near_other)} other "
        f"envelopes, e.g. {near_other[:1]!r}"
    )
    sub_deletes = _named(at_sub, "DeleteTable")
    assert sub_deletes == [], (
        f"the subject rule ({subject_rule}) matches eventName CreateTable only, so its sink must "
        f"hold no DeleteTable for any table: actual {len(sub_deletes)}, e.g. {sub_deletes[:1]!r}"
    )
    stray_at_ctl = [r for r in at_ctl if _env(r).get("source") == "aws.dynamodb"]
    assert stray_at_ctl == [], (
        f"the control rule matches aws.sqs only, so its sink must hold no aws.dynamodb event: "
        f"actual {len(stray_at_ctl)}"
    )

    # ---- in-body teardown of the slow pair: the cleanup chain has a 60 s ceiling ----------------
    _delete_trail_quietly(ct, trail_arn)
    _drain_and_delete_bucket(s3, bucket, _TEARDOWN_BUDGET_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
