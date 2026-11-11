"""event-history-is-independent-of-the-trail-lifecycle."""

# What this check asserts, and the timing it allows for:
#   H1  All three markers -- one made before any trail of ours existed, one while a trail was
#       logging, one after that trail was stopped AND deleted -- are returned by LookupEvents.
#       Docs: "The event history is separate from any trails or event data stores that you
#       create for your account. Changes you make to your event data stores or trails do not
#       affect the event history."
#   H2  Index latency. Management events can take a few minutes to appear in event history.
#       _INDEX_BUDGET_S is 255 s measured from the FIRST marker; the third marker is emitted
#       ~30 s later, so worst-case wall clock is ~290 s of polling plus ~30 s of setup plus
#       teardown.
#   H3  A closed past window is stable: three consecutive reads of the same explicit [start, end]
#       window return an identical set of EventIds.
#   H4  Each marker appears exactly ONCE in the window.
#   H5  Teardown drains a log bucket CloudTrail may still be writing to; it needs >= 180 s.

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-history-is-independent-of-the-trail-lifecycle"
GROUP = "data-plane"
SERVICES = ["cloudtrail"]

# A data-plane FAIL marker. A check detail containing this string is graded a real fidelity
# `fail` before any connection-error or not-implemented reading, so a target that never audits anything is scored as a mismatch
# rather than dropping out of the pass+fail denominator.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_INDEX_BUDGET_S = 255.0  # H2
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40
_FREEZE_READS = 3  # H3

# ===== helpers =====
# Every swallow is narrowed to ClientError.


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
    """Create-or-adopt an S3 bucket carrying the policy CloudTrail needs to deliver logs."""
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


def _error(fn):
    """The exact AWS (Error.Code, Error.Message), RAISING if the call unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
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


def _count_token(events, token):
    return sum(1 for ev in events if token in ev.get("CloudTrailEvent", ""))


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """Event history keeps recording this account's management calls across the whole life of a
    trail -- before one exists, while one is logging, and after it has been stopped and deleted --
    and a closed past window read three times returns the same EventId set.
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    # --- Marker A: emitted first, so the index has the longest possible time to catch up, and
    # so that it is unambiguously made before this check owns any trail.
    token_a = ctx.unique_name("sim2realcthista").lower()
    emitted_a = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    ct.describe_trails(trailNameList=[token_a])

    bucket = ctx.unique_name("sim2real-behav-cthist-")
    trail_name = ctx.unique_name("sim2real-behav-cthist-")
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
    _call(lambda: ct.start_logging(Name=trail_name))
    logging_status = _call(lambda: ct.get_trail_status(Name=trail_name))
    assert logging_status["IsLogging"] is True, (
        f"GetTrailStatus reports IsLogging={logging_status.get('IsLogging')!r} right after "
        f"StartLogging on {trail_name!r}; expected True, or marker B is not 'while a trail is "
        f"logging' at all"
    )

    # --- Marker B: while the trail is logging.
    token_b = ctx.unique_name("sim2realcthistb").lower()
    emitted_b = datetime.datetime.now(datetime.timezone.utc)
    ct.describe_trails(trailNameList=[token_b])

    # --- Kill the trail, and prove it dead before emitting marker C.
    _call(lambda: ct.stop_logging(Name=trail_name))
    stopped = _call(lambda: ct.get_trail_status(Name=trail_name))
    assert stopped["IsLogging"] is False, (
        f"GetTrailStatus reports IsLogging={stopped.get('IsLogging')!r} after StopLogging on "
        f"{trail_name!r}; expected False"
    )
    _call(lambda: ct.delete_trail(Name=trail_name))
    code, message = _error(lambda: ct.get_trail_status(Name=trail_name))
    assert code == "TrailNotFoundException", (
        f"GetTrailStatus on the deleted trail {trail_name!r} answered {code!r}, expected "
        f"TrailNotFoundException -- marker C is only meaningful if the trail is really gone"
    )
    assert message == (
        f"Unknown trail: arn:aws:cloudtrail:{region}:{account}:trail/{trail_name} "
        f"for the user: {account}"
    ), message
    code, message = _error(lambda: ct.start_logging(Name=trail_name))
    assert code == "TrailNotFoundException", (
        f"StartLogging -- which succeeded on {trail_name!r} minutes ago -- answered {code!r} on "
        f"the deleted name, expected TrailNotFoundException; the dead trail must be unusable"
    )
    assert message == (
        f"Unknown trail: arn:aws:cloudtrail:{region}:{account}:trail/{trail_name} "
        f"for the user: {account}"
    ), message

    # --- Marker C: after the trail is stopped and deleted.
    token_c = ctx.unique_name("sim2realcthistc").lower()
    emitted_c = datetime.datetime.now(datetime.timezone.utc)
    ct.describe_trails(trailNameList=[token_c])

    # --- All three must be indexed. Bounded, raises on expiry.
    window_start = emitted_a - datetime.timedelta(minutes=2)
    found: dict[str, dict] = {}
    polls = 0
    scanned = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        events = _lookup_all(
            ct,
            StartTime=window_start,
            EndTime=datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=5),
            MaxResults=50,
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}
            ],
        )
        scanned = len(events)
        for label, token in (("A", token_a), ("B", token_b), ("C", token_c)):
            if label in found:
                continue
            for ev in events:
                if token in ev.get("CloudTrailEvent", ""):
                    found[label] = ev
                    break
        if len(found) == 3:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert len(found) == 3, (
        f"{DATAPLANE_MARKER}: event history did not return all three of this check's own calls. "
        f"Found {sorted(found)!r}, missing "
        f"{sorted({'A', 'B', 'C'} - set(found))!r} after {polls} polls over {waited:.0f}s "
        f"scanning {scanned} DescribeTrails events. A was made before trail {trail_name!r} "
        f"existed ({emitted_a.isoformat()}), B while it was logging ({emitted_b.isoformat()}), "
        f"C after it was stopped and deleted ({emitted_c.isoformat()}). Real AWS indexed markers "
        f"of this shape in 80-136s. A target missing A or C has coupled event history to a "
        f"trail's existence; real AWS keeps them separate."
    )

    # --- Each record describes the call that produced it, so "found" is not a token substring
    # matching some unrelated event.
    for label, token, emitted in (
        ("A", token_a, emitted_a), ("B", token_b, emitted_b), ("C", token_c, emitted_c),
    ):
        record = json.loads(found[label]["CloudTrailEvent"])
        assert record["requestParameters"] == {"trailNameList": [token]}, (
            f"marker {label}: the record must reproduce the request verbatim; the call passed "
            f"trailNameList=[{token!r}] but the record carries "
            f"{record.get('requestParameters')!r}"
        )
        assert record["eventSource"] == "cloudtrail.amazonaws.com", (
            f"marker {label}: eventSource is {record.get('eventSource')!r}, expected "
            f"cloudtrail.amazonaws.com"
        )
        assert record["recipientAccountId"] == account, (
            f"marker {label}: recipientAccountId is {record.get('recipientAccountId')!r}, "
            f"expected {account!r}"
        )
        assert record["awsRegion"] == region, (
            f"marker {label}: awsRegion is {record.get('awsRegion')!r}, expected {region!r}"
        )
        assert found[label]["EventId"] == record["eventID"], (
            f"marker {label}: envelope EventId {found[label]['EventId']!r} disagrees with the "
            f"embedded record's eventID {record.get('eventID')!r}"
        )

    ids = {label: found[label]["EventId"] for label in ("A", "B", "C")}
    assert len(set(ids.values())) == 3, (
        f"the three markers were assigned only {len(set(ids.values()))} distinct EventIds: "
        f"{ids!r}. Three separate calls are three separate events"
    )

    # --- Freeze detector (H3, H4). The window is CLOSED: both bounds are fixed instants in the
    # past, so a correct target must answer identically however many times it is asked. Reading
    # must not advance state, and a marker must not be duplicated by the act of reading.
    freeze_end = datetime.datetime.now(datetime.timezone.utc)
    id_sets = []
    counts = []
    for _ in range(_FREEZE_READS):
        events = _lookup_all(
            ct,
            StartTime=window_start,
            EndTime=freeze_end,
            MaxResults=50,
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}
            ],
        )
        id_sets.append(frozenset(ev["EventId"] for ev in events))
        counts.append(
            tuple(_count_token(events, tok) for tok in (token_a, token_b, token_c))
        )
    assert len(set(id_sets)) == 1, (
        f"{_FREEZE_READS} consecutive reads of the SAME closed window "
        f"[{window_start.isoformat()}, {freeze_end.isoformat()}] returned "
        f"{len(set(id_sets))} different EventId sets; sizes were "
        f"{[len(s) for s in id_sets]!r} and the symmetric differences were "
        f"{[sorted(id_sets[0] ^ s) for s in id_sets[1:]]!r}. A closed past window is immutable; "
        f"a target that re-derives event history per call, or appends on read, fails here"
    )
    assert counts == [(1, 1, 1)] * _FREEZE_READS, (
        f"each of this run's three markers must appear EXACTLY ONCE in the window; the "
        f"{_FREEZE_READS} reads counted (A, B, C) as {counts!r}. A count above 1 means one API "
        f"call produced several records; a count of 0 in a later read means the store is not "
        f"stable"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
