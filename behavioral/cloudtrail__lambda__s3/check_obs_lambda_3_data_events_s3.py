"""obs-lambda-3-data-events-s3."""

# An Invoke data event carries requestParameters == {"functionName": <unqualified ARN>} only;
# the qualified name is in additionalEventData.functionVersion ("<arn>:$LATEST").

from __future__ import annotations

import datetime
import gzip
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-lambda-3-data-events-s3"
GROUP = "eventing"
SERVICES = ["cloudtrail", "lambda", "s3"]

_EVENT_SOURCE = "lambda.amazonaws.com"
_GET_EVENT = "GetFunction20150331v2"  # CloudTrail's eventName for GetFunction

_DELIVERY_BUDGET_S = 900.0
_INDEX_BUDGET_S = 420.0
_ROLE_PROPAGATION_BUDGET_S = 90.0
_ACTIVE_BUDGET_S = 90.0
_ROUND_INTERVAL_S = 20.0
_DRAIN_BUDGET_S = 45.0
_POLL_S = 2.0
_PAGE_CEILING = 40

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "ResourceNotFoundException",
            "NoSuchEntity",
            "TrailNotFoundException",
        ):
            raise


def _create_role(ctx, iam):
    """An execution role with NO permission policy. Invoke still works, and without logs:* the
    function cannot create a /aws/lambda/<fn> log group that would outlive it."""
    name = ctx.unique_name("sim2real-xsvc-ctd-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=name)))
    return arn


def _create_function(ctx, lam, logs, name, role_arn, code):
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{name}"))
    )
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": code},
                Description=f"sim2real {CHECK}",
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message") or ""
            if "cannot be assumed" not in msg or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: lam.delete_function(FunctionName=name)))
    return resp["FunctionArn"]


def _wait_active(lam, name):
    deadline = time.monotonic() + _ACTIVE_BUDGET_S
    while lam.get_function_configuration(FunctionName=name).get("State") != "Active":
        if time.monotonic() >= deadline:
            raise AssertionError(f"function {name} not Active within {_ACTIVE_BUDGET_S:.0f}s")
        time.sleep(2.0)


def _create_log_bucket(ctx, s3, account_id):
    bucket = ctx.unique_name("sim2real-xsvc-ctd-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
                        "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                    },
                ],
            }
        ),
    )
    return bucket


def _drain_and_delete_bucket(s3, bucket):
    """Bounded so a cleanup raises rather than hanging."""
    deadline = time.monotonic() + _DRAIN_BUDGET_S
    while True:
        try:
            for key in _list_keys(s3, bucket, ""):
                s3.delete_object(Bucket=bucket, Key=key)
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise RuntimeError(f"s3 bucket {bucket}: {code}") from exc
        time.sleep(_POLL_S)


def _list_keys(s3, bucket, prefix):
    keys, token = [], None
    while True:
        kw = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        keys.extend(o["Key"] for o in page.get("Contents", []))
        token = page.get("NextContinuationToken")
        if not token:
            return keys


def _delivered_records(s3, bucket, account_id):
    """Every record in every delivered gzipped log file. The terminal read."""
    out = []
    for key in _list_keys(s3, bucket, f"AWSLogs/{account_id}/CloudTrail/"):
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if not body:
            # CloudTrail leaves a zero-byte marker at the bare prefix; not a log file.
            continue
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as fh:
            out.extend(json.loads(fh.read().decode("utf-8")).get("Records", []))
    return out


def _invokes_naming(records, arn):
    return [
        r
        for r in records
        if r.get("eventName") == "Invoke" and arn in json.dumps(r.get("requestParameters") or {})
    ]


def _lookup_all(ct, **kw):
    out = []
    for _ in range(_PAGE_CEILING):
        resp = ct.lookup_events(**kw)
        out.extend(resp.get("Events", []))
        token = resp.get("NextToken")
        if not token:
            return out
        kw["NextToken"] = token
    raise AssertionError(f"LookupEvents paged past {_PAGE_CEILING} pages without exhausting")


def _invoke(lam, name, marker):
    resp = lam.invoke(FunctionName=name, Payload=json.dumps({"marker": marker}).encode())
    body = json.loads(resp["Payload"].read())
    assert resp["StatusCode"] == 200 and body == {"marker": marker}, (
        f"Invoke of {name} must genuinely run the function, or its absence from the trail means "
        f"nothing: expected 200 echoing {marker!r}, actual {resp['StatusCode']!r} {body!r}"
    )
    return resp["ResponseMetadata"]["RequestId"]


def _stop_logging(ct, trail_arn):
    _ignore_not_found(lambda: ct.stop_logging(Name=trail_arn))


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c3",
)
def run(ctx) -> None:
    """A trail whose advanced event selector names one function's ARN delivers that function's
    Invoke data events to S3 and withholds a second function's, and neither function's Invoke
    appears in LookupEvents management-event history.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def lambda_handler(event, context):\n    return event\n")
    code = buf.getvalue()

    # The bucket is registered first so LIFO drains it LAST, after the trail stops writing to it.
    bucket = _create_log_bucket(ctx, s3, account_id)
    role_arn = _create_role(ctx, iam)
    fn_a = ctx.unique_name("sim2real-xsvc-ctd-a-")
    fn_b = ctx.unique_name("sim2real-xsvc-ctd-b-")
    arn_a = _create_function(ctx, lam, logs, fn_a, role_arn, code)
    arn_b = _create_function(ctx, lam, logs, fn_b, role_arn, code)
    _wait_active(lam, fn_a)
    _wait_active(lam, fn_b)

    trail_name = ctx.unique_name("sim2real-xsvc-ctd-")
    trail_arn = ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )["TrailARN"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ct.delete_trail(Name=trail_arn)))
    field_selectors = [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]},
        {"Field": "resources.ARN", "Equals": [arn_a]},
    ]
    ct.put_event_selectors(
        TrailName=trail_arn,
        AdvancedEventSelectors=[{"Name": "fnA-only", "FieldSelectors": field_selectors}],
    )
    stored = ct.get_event_selectors(TrailName=trail_arn).get("AdvancedEventSelectors") or []
    stored_fields = sorted(json.dumps(f, sort_keys=True) for s in stored for f in s["FieldSelectors"])
    want_fields = sorted(json.dumps(f, sort_keys=True) for f in field_selectors)
    assert stored_fields == want_fields, (
        f"the stored advanced selector must hold exactly the three field selectors: expected "
        f"{want_fields!r}, actual {stored_fields!r}"
    )
    ct.start_logging(Name=trail_arn)
    ctx.on_cleanup(lambda: _stop_logging(ct, trail_arn))

    # ---- invoke in rounds until fnA's data events are demonstrably flowing ------------------------
    # The selector goes live some time after StartLogging returns, and invokes made before then
    # are never delivered, so a single invoke is not enough.
    a_request_ids: list[str] = []
    b_request_ids: list[str] = []
    records: list[dict] = []
    delivery_s = _budget_s(ctx, _DELIVERY_BUDGET_S)
    deadline = time.monotonic() + delivery_s
    rounds = 0
    next_round_at = time.monotonic()
    while True:
        if time.monotonic() >= next_round_at:
            a_request_ids.append(_invoke(lam, fn_a, f"a-{rounds}"))
            b_request_ids.append(_invoke(lam, fn_b, f"b-{rounds}"))
            rounds += 1
            next_round_at = time.monotonic() + _ROUND_INTERVAL_S
        records = _delivered_records(s3, bucket, account_id)
        if _invokes_naming(records, arn_a):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"an Invoke data event for fnA ({arn_a}) in s3://{bucket}: the run budget ended "
                    f"first; not graded"
                )
            raise AssertionError(
                f"no Invoke data event for fnA ({arn_a}) was delivered to s3://{bucket} within "
                f"{delivery_s:.0f}s over {rounds} invoke rounds: expected >=1, actual 0 of "
                f"{len(records)} delivered records"
            )
        time.sleep(_POLL_S)

    # ---- barrier: fnB first, then fnA; wait for fnA's barrier record by requestID -----------------
    b_request_ids.append(_invoke(lam, fn_b, "b-barrier"))
    barrier_id = _invoke(lam, fn_a, "a-barrier")
    a_request_ids.append(barrier_id)
    lam.get_function(FunctionName=fn_a)  # the management-event barrier for the LookupEvents leg
    while True:
        records = _delivered_records(s3, bucket, account_id)
        if any(r.get("requestID") == barrier_id for r in _invokes_naming(records, arn_a)):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"fnA's barrier Invoke (requestID {barrier_id}) delivery: the run budget ended "
                    f"first; not graded"
                )
            raise AssertionError(
                f"fnA's barrier Invoke (requestID {barrier_id}) was not delivered within "
                f"{delivery_s:.0f}s although earlier fnA invokes were: actual requestIDs "
                f"{sorted(r.get('requestID') for r in _invokes_naming(records, arn_a))!r}"
            )
        time.sleep(_POLL_S)

    a_records = _invokes_naming(records, arn_a)
    # A trail can still carry a few MANAGEMENT records (CreateFunction for fnB) processed
    # before its data-only selector took effect, so the absence is over data events and Invokes.
    b_records = [
        r
        for r in records
        if (r.get("eventName") == "Invoke" or r.get("eventCategory") == "Data")
        and fn_b in json.dumps(r)
    ]

    # Leg 1: fnA's records, with the shape real AWS gives a Lambda data event.
    for rec in a_records:
        assert rec.get("eventSource") == _EVENT_SOURCE, (
            f"eventSource: expected {_EVENT_SOURCE!r}, actual {rec.get('eventSource')!r}"
        )
        assert rec.get("eventCategory") == "Data" and rec.get("managementEvent") is False, (
            "an Invoke is a data event: expected eventCategory 'Data' and managementEvent False, actual "
            f"{rec.get('eventCategory')!r} / {rec.get('managementEvent')!r}"
        )
        assert rec.get("readOnly") is False, (
            f"Invoke is recorded as a write: expected readOnly False, actual {rec.get('readOnly')!r}"
        )
        assert (rec.get("requestParameters") or {}).get("functionName") == arn_a, (
            f"requestParameters.functionName must be fnA's unqualified ARN {arn_a!r}: actual "
            f"{(rec.get('requestParameters') or {}).get('functionName')!r}"
        )
        assert (rec.get("additionalEventData") or {}).get("functionVersion") == f"{arn_a}:$LATEST", (
            f"additionalEventData.functionVersion must be the QUALIFIED name {arn_a + ':$LATEST'!r}: "
            f"actual {(rec.get('additionalEventData') or {}).get('functionVersion')!r}"
        )
        assert {"accountId": account_id, "type": "AWS::Lambda::Function", "ARN": arn_a} in (
            rec.get("resources") or []
        ), f"resources must name fnA as an AWS::Lambda::Function: actual {rec.get('resources')!r}"
        assert rec.get("recipientAccountId") == account_id and rec.get("awsRegion") == ctx.region, (
            f"account/region: expected {account_id!r}/{ctx.region!r}, actual "
            f"{rec.get('recipientAccountId')!r}/{rec.get('awsRegion')!r}"
        )
    delivered_ids = {r.get("requestID") for r in a_records}
    assert delivered_ids <= set(a_request_ids), (
        "every delivered fnA record must correspond to an Invoke this check made: unexpected "
        f"requestIDs {sorted(delivered_ids - set(a_request_ids))!r}"
    )

    # Leg 2: fnB is withheld, although its last invoke ran BEFORE fnA's delivered barrier.
    assert b_records == [], (
        f"the selector names only fnA, so NO record may name fnB ({arn_b}): expected 0, actual "
        f"{len(b_records)} -- {[r.get('eventName') for r in b_records]!r}. fnB was invoked "
        f"{len(b_request_ids)} times, the last immediately before fnA's barrier, which WAS delivered "
        f"({len(a_records)} fnA records over {len(records)} total)"
    )

    # Leg 3: data events never enter management-event history. Barrier: the GetFunction made after
    # the last invoke is already indexed.
    index_s = _budget_s(ctx, _INDEX_BUDGET_S)
    index_deadline = time.monotonic() + index_s
    while True:
        indexed = [
            json.loads(e["CloudTrailEvent"])
            for e in _lookup_all(
                ct,
                LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": _EVENT_SOURCE}],
                StartTime=start,
            )
        ]
        mine = [r for r in indexed if fn_a in json.dumps(r) or fn_b in json.dumps(r)]
        if any(
            r.get("eventName") == _GET_EVENT
            and (r.get("requestParameters") or {}).get("functionName") == fn_a
            for r in mine
        ):
            break
        if time.monotonic() >= index_deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"the GetFunction barrier for {fn_a!r} to be indexed: the run budget ended "
                    f"first; not graded"
                )
            raise AssertionError(
                f"the GetFunction barrier for {fn_a!r} was not indexed within {index_s:.0f}s: "
                f"eventNames seen for the two functions {sorted({r.get('eventName') for r in mine})!r}"
            )
        time.sleep(_POLL_S)
    leaked = [r for r in mine if r.get("eventName") == "Invoke"]
    assert leaked == [], (
        "LookupEvents returns management events only; an Invoke data event must never appear there: "
        f"expected 0, actual {len(leaked)} ({[r.get('requestParameters') for r in leaked]!r})"
    )
    by_name = _lookup_all(
        ct, LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "Invoke"}], StartTime=start
    )
    mine_by_name = [e for e in by_name if fn_a in e["CloudTrailEvent"] or fn_b in e["CloudTrailEvent"]]
    assert mine_by_name == [], (
        f"LookupEvents(EventName=Invoke) must not return this check's invokes: expected 0, actual "
        f"{len(mine_by_name)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
