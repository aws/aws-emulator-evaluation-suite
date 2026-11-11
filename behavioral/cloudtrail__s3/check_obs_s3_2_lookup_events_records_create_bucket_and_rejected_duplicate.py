"""obs-s3-2-lookup-events-records-create-bucket-and-rejected-duplicate."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-s3-2-lookup-events-records-create-bucket-and-rejected-duplicate"
GROUP = "eventing"
SERVICES = ["cloudtrail", "s3"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# Event history indexing is documented as "within 15 minutes"; the budget is that bound.
_INDEX_BUDGET_S = 900.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 50
_DUP_MESSAGE = (
    "Your previous request to create the named bucket succeeded and you already own it."
)

def _error(fn):
    """Call fn() and return its (Error.Code, Error.Message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _delete_bucket(s3, bucket):
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded); LookupEvents is limited to 2 TPS per account."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        for attempt in range(6):
            try:
                resp = ct.lookup_events(**kw)
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ThrottlingException" or attempt == 5:
                    raise
                time.sleep(2.0 * (attempt + 1))
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
        time.sleep(0.6)
    return out


@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "cap:c2",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """LookupEvents records both a successful CreateBucket and the following duplicate CreateBucket,
    the latter with errorCode BucketAlreadyOwnedByYou, and the refusal leaves the bucket intact.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
    """
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    bucket = ctx.unique_name("sim2real-xsvc-ctlk-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}

    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    # Outside us-east-1 the owner's duplicate CreateBucket is refused; us-east-1 historically
    # returns 200, so this expectation holds in every other region.
    code, message = _error(lambda: s3.create_bucket(**kw))
    assert code == "BucketAlreadyOwnedByYou", (
        f"a duplicate CreateBucket by the owner: expected 'BucketAlreadyOwnedByYou', actual {code!r}"
    )
    assert message == _DUP_MESSAGE, (
        f"a duplicate CreateBucket by the owner: expected message {_DUP_MESSAGE!r}, actual {message!r}"
    )
    # The original bucket is still there and still ours.
    s3.head_bucket(Bucket=bucket)
    loc = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    want_loc = None if ctx.region == "us-east-1" else ctx.region
    assert loc == want_loc, f"bucket location after the refused duplicate: {loc!r}, expected {want_loc!r}"

    deadline = time.monotonic() + _INDEX_BUDGET_S
    while True:
        events = _lookup_all(
            ct,
            LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "s3.amazonaws.com"}],
            StartTime=start,
            EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1),
            MaxResults=50,
        )
        ours = {}
        for e in events:
            if e.get("EventName") != "CreateBucket":
                continue
            rec = json.loads(e["CloudTrailEvent"])
            if (rec.get("requestParameters") or {}).get("bucketName") == bucket:
                ours.setdefault(rec.get("eventID"), (e, rec))
        ok = [v for v in ours.values() if "errorCode" not in v[1]]
        dup = [v for v in ours.values() if "errorCode" in v[1]]
        if ok and dup:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: within {_INDEX_BUDGET_S:.0f}s LookupEvents(EventSource="
                f"s3.amazonaws.com) returned {len(events)} events but for bucket {bucket!r} only "
                f"{len(ok)} successful and {len(dup)} failed CreateBucket records (expected 1 and 1)"
            )
        time.sleep(_POLL_INTERVAL_S)

    assert len(ok) == 1 and len(dup) == 1, (
        f"expected exactly one successful and one failed CreateBucket for {bucket!r}, actual "
        f"{len(ok)} and {len(dup)}"
    )
    for label, (ev, rec) in (("create", ok[0]), ("duplicate", dup[0])):
        assert ev.get("EventSource") == "s3.amazonaws.com", (
            f"{label}: EventSource expected 's3.amazonaws.com', actual {ev.get('EventSource')!r}"
        )
        assert rec.get("eventSource") == "s3.amazonaws.com", (
            f"{label}: record eventSource expected 's3.amazonaws.com', actual "
            f"{rec.get('eventSource')!r}"
        )
        assert rec.get("eventCategory") == "Management", (
            f"{label}: eventCategory expected 'Management', actual {rec.get('eventCategory')!r}"
        )
        assert rec.get("managementEvent") is True, (
            f"{label}: managementEvent expected True, actual {rec.get('managementEvent')!r}"
        )
        assert rec.get("readOnly") is False, (
            f"{label}: CreateBucket writes, readOnly expected False, actual {rec.get('readOnly')!r}"
        )
        assert rec.get("awsRegion") == ctx.region, (
            f"{label}: awsRegion expected {ctx.region!r}, actual {rec.get('awsRegion')!r}"
        )
        assert ev.get("ReadOnly") == "false", (
            f"{label}: LookupEvents ReadOnly expected 'false', actual {ev.get('ReadOnly')!r}"
        )
    _, created = ok[0]
    _, refused = dup[0]
    assert "errorMessage" not in created, (
        f"the successful CreateBucket must carry no errorMessage, actual {created.get('errorMessage')!r}"
    )
    assert refused.get("errorCode") == "BucketAlreadyOwnedByYou", (
        f"the refused CreateBucket's errorCode: expected 'BucketAlreadyOwnedByYou', actual "
        f"{refused.get('errorCode')!r}"
    )
    assert refused.get("errorMessage") == _DUP_MESSAGE, (
        f"the refused CreateBucket's errorMessage: expected {_DUP_MESSAGE!r}, actual "
        f"{refused.get('errorMessage')!r}"
    )
    assert refused["eventTime"] >= created["eventTime"], (
        f"the refusal must not precede the create: create {created['eventTime']!r}, duplicate "
        f"{refused['eventTime']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
