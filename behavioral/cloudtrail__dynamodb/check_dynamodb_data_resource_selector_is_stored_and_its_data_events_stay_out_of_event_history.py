"""dynamodb-data-resource-selector-is-stored-and-its-data-events-stay-out-of-event-history."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dynamodb-data-resource-selector-is-stored-and-its-data-events-stay-out-of-event-history"
GROUP = "eventing"
SERVICES = ["cloudtrail", "dynamodb"]

# Marks a failure as a missing data-plane behaviour rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_TABLE_ACTIVE_BUDGET_S = 120.0
_PAGE_CEILING = 40

_DATA_OPERATIONS = ("PutItem", "GetItem")


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    """Invoke fn(), retrying transient CloudTrail control-plane errors. Raises the last error."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_trail_bucket(s3, bucket, region, account_id):
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "BucketAlreadyOwnedByYou", "BucketAlreadyExists",
        ):
            raise
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _purge_bucket_once(s3, bucket):
    removed = 0
    for paginator_name, list_key, id_key in (
        ("list_objects_v2", "Contents", None),
        ("list_object_versions", "Versions", "VersionId"),
        ("list_object_versions", "DeleteMarkers", "VersionId"),
    ):
        paginator = s3.get_paginator(paginator_name)
        try:
            for page in paginator.paginate(Bucket=bucket):
                entries = page.get(list_key, [])
                if not entries:
                    continue
                objects = []
                for entry in entries:
                    item = {"Key": entry["Key"]}
                    if id_key and entry.get(id_key):
                        item["VersionId"] = entry[id_key]
                    objects.append(item)
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
                removed += len(objects)
        except ClientError:
            continue
    return removed


def _drain_and_delete_bucket(s3, bucket, *, attempts=8, delay_s=15.0):
    """Empty and delete the log bucket, retrying because CloudTrail may still be writing.
    RAISES on a deadline miss so a leaked billable bucket is visible."""
    last = None
    for attempt in range(attempts):
        _purge_bucket_once(s3, bucket)
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchBucket":
                return
            last = exc
            if attempt < attempts - 1:
                time.sleep(delay_s)
    raise AssertionError(
        f"could not delete trail log bucket {bucket} after {attempts} attempts; a billable S3 "
        f"bucket has been LEAKED. Last error: {last}"
    )


def _delete_trail_idempotent(ct, name):
    for fn in (lambda: ct.stop_logging(Name=name), lambda: ct.delete_trail(Name=name)):
        try:
            _call(fn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
                raise


def _delete_table_idempotent(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_table_gone(ddb, table_name, *, timeout_s=120.0, interval_s=2.0):
    """Poll DescribeTable until ResourceNotFoundException; RAISES on the deadline.

    DeleteTable is asynchronous: a PutItem right after it can still succeed once."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ddb.describe_table(TableName=table_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name!r} never became fully deleted within {timeout_s}s")


def _error_code(fn):
    """The exact AWS error code and message, RAISING if the call unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("call unexpectedly SUCCEEDED where an error was required")


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded)."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    return out


def _by_event_name(ct, name, *, start, end):
    return _lookup_all(
        ct, StartTime=start, EndTime=end, MaxResults=50,
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
    )


def _wait_table_active(ddb, table_name, *, timeout_s):
    """Poll DescribeTable until ACTIVE; RAISES on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if last == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(
        f"table {table_name!r} did not reach ACTIVE within {timeout_s}s; last status {last!r}. "
        f"No data operation can be issued against it, so nothing below is interpretable"
    )


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """A trail's AWS::DynamoDB::Table data selector round-trips, yet PutItem/GetItem never appear in
    event history while a later TagResource on the table does; every returned event is Management.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
    """
    ct = ctx.client("cloudtrail")
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    table_name = ctx.unique_name("sim2real-behav-ctddb-")
    table = ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TableDescription"]
    ctx.on_cleanup(lambda: _delete_table_idempotent(ddb, table_name))
    table_arn = table["TableArn"]
    _wait_table_active(ddb, table_name, timeout_s=_TABLE_ACTIVE_BUDGET_S)

    bucket = ctx.unique_name("sim2real-behav-ctddb-")
    trail_name = ctx.unique_name("sim2real-behav-ctddb-")
    _create_trail_bucket(s3, bucket, region, account)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    _call(lambda: ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    ))
    ctx.on_cleanup(lambda: _delete_trail_idempotent(ct, trail_name))

    # --- The baseline: a new trail logs management events and NO data events.
    baseline = _call(lambda: ct.get_event_selectors(TrailName=trail_name))["EventSelectors"]
    assert len(baseline) == 1, (
        f"a new trail reports {len(baseline)} event selector(s), expected exactly 1: {baseline!r}"
    )
    assert baseline[0]["DataResources"] == [], (
        f"a new trail reports DataResources {baseline[0]['DataResources']!r}; the documented "
        f"default is management events only, with no data resources at all. The delta this check "
        f"measures is meaningless if the default already selects data events"
    )
    assert baseline[0]["IncludeManagementEvents"] is True, (
        f"a new trail reports IncludeManagementEvents "
        f"{baseline[0].get('IncludeManagementEvents')!r}, expected True"
    )

    # --- the selector that names the table, stored as submitted plus AWS's default
    # ExcludeManagementEventSources: [], which both Put and Get echo back.
    submitted = [{
        "ReadWriteType": "All",
        "IncludeManagementEvents": True,
        "DataResources": [{"Type": "AWS::DynamoDB::Table", "Values": [table_arn]}],
    }]
    expected_stored = [{**submitted[0], "ExcludeManagementEventSources": []}]
    put_response = _call(
        lambda: ct.put_event_selectors(TrailName=trail_name, EventSelectors=submitted)
    )
    assert put_response["EventSelectors"] == expected_stored, (
        f"PutEventSelectors echoed {put_response['EventSelectors']!r}, expected the selector set "
        f"submitted plus AWS's own default ExcludeManagementEventSources ({expected_stored!r})"
    )
    stored = _call(lambda: ct.get_event_selectors(TrailName=trail_name))["EventSelectors"]
    assert stored == expected_stored, (
        f"GetEventSelectors returns {stored!r}, expected {expected_stored!r}. AWS::DynamoDB::Table "
        f"is one of the three types basic event selectors accept, and the ARN is this run's table "
        f"-- so a target that normalises the Type, reorders Values or drops DataResources entirely "
        f"fails here"
    )

    _call(lambda: ct.start_logging(Name=trail_name))
    status = _call(lambda: ct.get_trail_status(Name=trail_name))
    assert status["IsLogging"] is True, (
        f"GetTrailStatus reports IsLogging={status.get('IsLogging')!r} right after StartLogging on "
        f"{trail_name!r}; expected True. The data operations below must happen while the trail is "
        f"actively selecting them, or their absence from event history proves nothing"
    )

    # --- The DATA events, first.
    item_token = ctx.unique_name("sim2realctddbitem").lower()
    data_emitted_at = datetime.datetime.now(datetime.timezone.utc)
    ddb.put_item(
        TableName=table_name,
        Item={"pk": {"S": item_token}, "marker": {"S": item_token}},
    )
    got = ddb.get_item(TableName=table_name, Key={"pk": {"S": item_token}})
    assert got["Item"]["marker"]["S"] == item_token, (
        f"GetItem did not read back the item PutItem wrote: {got.get('Item')!r}. Both data "
        f"operations must genuinely have happened for their absence from event history to mean "
        f"anything"
    )

    # --- The MANAGEMENT marker, afterwards: issued after the data operations, its arrival proves
    # the index has advanced past them, so their absence below is not a race.
    mgmt_token = ctx.unique_name("sim2realctddbmgmt").lower()
    mgmt_emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    ddb.tag_resource(
        ResourceArn=table_arn, Tags=[{"Key": "sim2real-marker", "Value": mgmt_token}]
    )
    assert mgmt_emitted_at >= data_emitted_at, (
        f"the management marker must be emitted AFTER the data operations for the barrier "
        f"argument to hold; got {mgmt_emitted_at.isoformat()} vs {data_emitted_at.isoformat()}"
    )

    window_start = data_emitted_at - datetime.timedelta(minutes=2)
    mgmt_ev = None
    polls = 0
    scanned = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        events = _by_event_name(ct, "TagResource", start=window_start, end=window_end)
        scanned = len(events)
        for ev in events:
            if mgmt_token in ev.get("CloudTrailEvent", ""):
                mgmt_ev = ev
                break
        if mgmt_ev is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert mgmt_ev is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail produced no dynamodb:TagResource record for table "
        f"{table_name!r} carrying the token {mgmt_token!r}, after {polls} polls over "
        f"{waited:.0f}s scanning {scanned} TagResource events. This is the positive control and "
        f"the barrier: without it the data-event absences below cannot be distinguished from a "
        f"target that audits no DynamoDB activity at all"
    )
    mgmt_record = json.loads(mgmt_ev["CloudTrailEvent"])
    assert mgmt_record["eventSource"] == "dynamodb.amazonaws.com", (
        f"the TagResource record's eventSource is {mgmt_record.get('eventSource')!r}, expected "
        f"dynamodb.amazonaws.com"
    )
    assert mgmt_record["eventCategory"] == "Management", (
        f"dynamodb:TagResource is audited with eventCategory "
        f"{mgmt_record.get('eventCategory')!r}, expected Management -- tagging is a control-plane "
        f"act, and if the target classifies it as Data the partition under test is inverted"
    )
    assert table_arn in json.dumps(mgmt_record["requestParameters"]), (
        f"the TagResource record's requestParameters {mgmt_record['requestParameters']!r} do not "
        f"name the table ARN the call addressed ({table_arn!r}), so the record does not connect "
        f"this management event to this table"
    )

    # --- The absences, over a CLOSED window the index has demonstrably passed.
    absence_end = datetime.datetime.now(datetime.timezone.utc)
    for operation in _DATA_OPERATIONS:
        events = _by_event_name(ct, operation, start=window_start, end=absence_end)
        leaked = [
            ev for ev in events
            if table_name in ev.get("CloudTrailEvent", "")
            or table_arn in ev.get("CloudTrailEvent", "")
            or item_token in ev.get("CloudTrailEvent", "")
        ]
        assert leaked == [], (
            f"dynamodb:{operation} is a DATA event, and event history is management-only -- yet "
            f"LookupEvents returned {len(leaked)} {operation} event(s) naming this run's table "
            f"({table_name!r}) or its item token: "
            f"{[ev.get('EventId') for ev in leaked]!r}. The trail's selectors DO name this table "
            f"(asserted above) and the trail was logging, so the events were selected for the "
            f"trail; they must still be absent from the 90-day event-history surface. A target "
            f"serving LookupEvents out of one flat event store leaks them here, and the "
            f"management marker {mgmt_token!r} found in the same window proves the index is live "
            f"and has advanced past the instant these operations occupied"
        )

    everything = _lookup_all(
        ct, StartTime=window_start, EndTime=absence_end, MaxResults=50
    )
    assert everything, (
        f"an unfiltered LookupEvents over [{window_start.isoformat()}, "
        f"{absence_end.isoformat()}] returned no events at all, yet the TagResource marker was "
        f"found in that same window moments ago; the assertion below would pass vacuously"
    )
    non_management = [
        (ev["EventId"], json.loads(ev["CloudTrailEvent"]).get("eventCategory"))
        for ev in everything
        if json.loads(ev["CloudTrailEvent"]).get("eventCategory") != "Management"
    ]
    assert non_management == [], (
        f"{len(non_management)} of {len(everything)} events an unfiltered LookupEvents returned "
        f"carry an eventCategory other than Management: {non_management[:5]!r}. Event history "
        f"shows management events only -- data and Insights events require a trail or an event "
        f"data store. This is the general form of the per-operation absences above, and it holds "
        f"regardless of which data events happen to be flowing in the account"
    )

    # --- prove the teardown, using operations that demonstrably worked earlier in this run.
    _call(lambda: ct.stop_logging(Name=trail_name))
    _call(lambda: ct.delete_trail(Name=trail_name))
    code, message = _error_code(lambda: ct.get_event_selectors(TrailName=trail_name))
    assert code == "TrailNotFoundException", (
        f"GetEventSelectors on the deleted trail {trail_name!r} -- which returned the "
        f"AWS::DynamoDB::Table selector minutes ago -- answered {code!r}, expected "
        f"TrailNotFoundException"
    )
    assert message == f"Unknown trail: {put_response['TrailARN']} for the user: {ctx.account}", (
        f"expected the exact TrailNotFoundException message AWS returns, got {message!r}"
    )
    ddb.delete_table(TableName=table_name)
    # DeleteTable is asynchronous; a PutItem right after it can still succeed once.
    _wait_table_gone(ddb, table_name)
    code, message = _error_code(lambda: ddb.put_item(
        TableName=table_name, Item={"pk": {"S": item_token}}
    ))
    assert code == "ResourceNotFoundException", (
        f"PutItem on the deleted table {table_name!r} -- which succeeded earlier in this run -- "
        f"answered {code!r}, expected ResourceNotFoundException; a deleted table must be "
        f"unusable, not merely unreadable"
    )
    assert message == "Requested resource not found", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
