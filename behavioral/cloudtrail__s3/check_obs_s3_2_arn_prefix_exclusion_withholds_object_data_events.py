"""obs-s3-2-arn-prefix-exclusion-withholds-object-data-events."""
from __future__ import annotations

import gzip
import io
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-s3-2-arn-prefix-exclusion-withholds-object-data-events"
GROUP = "eventing"
SERVICES = ["cloudtrail", "s3"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# Data events are documented as delivered roughly every 5 minutes; 600 s is 2x that.
_DELIVERY_BUDGET_S = 600.0
# After every expected record has landed on BOTH trails, keep polling the excluding trail this
# long for a straggler: a poll catches a record that lands mid-window, a bare sleep does not.
_HOLD_BUDGET_S = 120.0
_CLEANUP_BUDGET_S = 240.0
_POLL_INTERVAL_S = 2.0
_ROUND_INTERVAL_S = 30.0  # spacing between repeated call rounds, not a poll interval
_MAX_ROUNDS = 20

def _create_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix)
    kw = {"Bucket": name}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _drain_and_delete_bucket(s3, bucket):
    """Empty and delete the bucket, raising on a deadline miss so a leak is visible.

    A trail can still write a final log file after StopLogging/DeleteTrail.
    """
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        keys = []
        token = None
        while True:
            kw = {"Bucket": bucket, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            try:
                page = s3.list_objects_v2(**kw)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "NoSuchBucket":
                    return
                raise
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
                f"bucket {bucket} still not empty after {_CLEANUP_BUDGET_S:.0f}s"
            )
        time.sleep(10.0)


def _attach_trail_policy(s3, bucket, account_id, key_prefixes):
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
                        "Resource": [
                            f"arn:aws:s3:::{bucket}/{p}/AWSLogs/{account_id}/*"
                            for p in key_prefixes
                        ],
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            }
        ),
    )


def _delivered_records(s3, bucket, key_prefix):
    """Every record in every gzipped log file one trail delivered under its own key prefix."""
    keys = []
    token = None
    while True:
        kw = {"Bucket": bucket, "Prefix": f"{key_prefix}/AWSLogs/", "MaxKeys": 1000}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        keys.extend(o["Key"] for o in page.get("Contents", []) if o["Key"].endswith(".json.gz"))
        token = page.get("NextContinuationToken")
        if not token:
            break
    out = []
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if not body:
            continue
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as fh:
            out.extend(json.loads(fh.read().decode("utf-8")).get("Records", []))
    return out


def _find(records, event_name, bucket, key):
    out = {}
    for r in records:
        params = r.get("requestParameters") or {}
        if (r.get("eventName") == event_name and params.get("bucketName") == bucket
                and params.get("key") == key):
            out.setdefault(r.get("eventID"), r)
    return list(out.values())


def _keys_under(records, bucket, prefix):
    return sorted(
        {
            (r.get("eventName"), (r.get("requestParameters") or {}).get("key"))
            for r in records
            if (r.get("requestParameters") or {}).get("bucketName") == bucket
            and str((r.get("requestParameters") or {}).get("key") or "").startswith(prefix)
        }
    )


def _stop_logging_quietly(ct, trail_arn):
    try:
        ct.stop_logging(Name=trail_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
            raise


def _by_field(selectors):
    return [
        (s.get("Name"), sorted(json.dumps(f, sort_keys=True) for f in s.get("FieldSelectors") or []))
        for s in selectors or []
    ]


def _make_trail(ctx, ct, log_bucket, key_prefix, selectors):
    name = ctx.unique_name("sim2real-xsvc-ct-")
    arn = ct.create_trail(
        Name=name,
        S3BucketName=log_bucket,
        S3KeyPrefix=key_prefix,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )["TrailARN"]
    ctx.on_cleanup(lambda: ct.delete_trail(Name=arn))
    ct.put_event_selectors(TrailName=arn, AdvancedEventSelectors=selectors)
    stored = ct.get_event_selectors(TrailName=arn).get("AdvancedEventSelectors")
    # AWS echoes the field selectors re-ordered by Field name, so compare per Field.
    assert _by_field(stored) == _by_field(selectors), (
        f"the advanced selectors must read back as submitted (any field order): expected "
        f"{selectors!r}, actual {stored!r}"
    )
    ct.start_logging(Name=arn)
    ctx.on_cleanup(lambda: _stop_logging_quietly(ct, arn))
    is_logging = ct.get_trail_status(Name=arn).get("IsLogging")
    assert is_logging is True, f"trail {name} must be logging, got {is_logging!r}"
    return arn


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An advanced selector combining resources.ARN StartsWith (the bucket) and NotStartsWith (one
    prefix) delivers object data events outside the prefix and withholds every one under it.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/filtering-data-events.html
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    payload = b"sim2real-cloudtrail-arn-exclusion"

    log_bucket = _create_bucket(ctx, "sim2real-xsvc-ctlog-")
    _attach_trail_policy(s3, log_bucket, account_id, ["excl", "ctrl"])
    data_bucket = _create_bucket(ctx, "sim2real-xsvc-ctdata-")
    bucket_arn_prefix = f"arn:aws:s3:::{data_bucket}/"
    excluded_arn_prefix = f"arn:aws:s3:::{data_bucket}/excluded/"

    def _selector(name, arn_field):
        return [
            {
                "Name": name,
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                    arn_field,
                ],
            }
        ]

    # A control trail without NotStartsWith proves the excluded calls were delivery-eligible;
    # a barrier Put issued last proves the excluding trail is live and caught up.
    _make_trail(ctx, ct, log_bucket, "excl", _selector(
        "objects-except-excluded-prefix",
        {"Field": "resources.ARN", "StartsWith": [bucket_arn_prefix],
         "NotStartsWith": [excluded_arn_prefix]},
    ))
    _make_trail(ctx, ct, log_bucket, "ctrl", _selector(
        "all-objects-in-bucket",
        {"Field": "resources.ARN", "StartsWith": [bucket_arn_prefix]},
    ))

    k = ctx.unique_name("k")

    def _round(r):
        key_in, key_out, key_barrier = f"included/{k}-{r}", f"excluded/{k}-{r}", f"included/barrier-{k}-{r}"
        s3.put_object(Bucket=data_bucket, Key=key_in, Body=payload)
        got = s3.get_object(Bucket=data_bucket, Key=key_in)["Body"].read()
        assert got == payload, f"GetObject included/ returned {got!r}, expected {payload!r}"
        s3.put_object(Bucket=data_bucket, Key=key_out, Body=payload)
        got = s3.get_object(Bucket=data_bucket, Key=key_out)["Body"].read()
        assert got == payload, (
            f"GetObject excluded/ must genuinely succeed or its absence means nothing: got {got!r}"
        )
        s3.put_object(Bucket=data_bucket, Key=key_barrier, Body=payload)
        ctrl_wanted = {
            ("PutObject", key_in), ("GetObject", key_in),
            ("PutObject", key_out), ("GetObject", key_out),
            ("PutObject", key_barrier),
        }
        excl_wanted = {("PutObject", key_in), ("GetObject", key_in), ("PutObject", key_barrier)}
        return key_out, key_barrier, ctrl_wanted, excl_wanted

    # Calls made within seconds of StartLogging may never be delivered, and nothing reports when a
    # fresh trail starts capturing, so repeat the sequence on fresh keys and grade the first round
    # complete on both trails.
    rounds = []
    graded = None
    ctrl, excl = [], []
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    next_round = time.monotonic()
    while graded is None:
        if len(rounds) < _MAX_ROUNDS and time.monotonic() >= next_round:
            rounds.append(_round(len(rounds)))
            next_round = time.monotonic() + _ROUND_INTERVAL_S
        time.sleep(_POLL_INTERVAL_S)
        ctrl = _delivered_records(s3, log_bucket, "ctrl")
        excl = _delivered_records(s3, log_bucket, "excl")
        for rnd in rounds:
            _, _, ctrl_wanted, excl_wanted = rnd
            if all(_find(ctrl, w[0], data_bucket, w[1]) for w in ctrl_wanted) and all(
                _find(excl, w[0], data_bucket, w[1]) for w in excl_wanted
            ):
                graded = rnd
                break
        if graded is None and time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: within {_DELIVERY_BUDGET_S:.0f}s, over {len(rounds)} rounds, no "
                f"round was complete on both trails (control delivered {len(ctrl)} records, "
                f"excluding trail {len(excl)})"
            )
    key_out, key_barrier, ctrl_wanted, excl_wanted = graded
    excluded_key_suffix = key_out[len("excluded/"):]

    # The control trail recorded the excluded calls as data events on the right object ARN.
    for event_name in ("PutObject", "GetObject"):
        rec = _find(ctrl, event_name, data_bucket, key_out)[0]
        arns = [r.get("ARN") for r in rec.get("resources") or [] if r.get("type") == "AWS::S3::Object"]
        assert arns == [f"{excluded_arn_prefix}{excluded_key_suffix}"], (
            f"control trail {event_name} excluded/ record: expected object ARN "
            f"{excluded_arn_prefix + excluded_key_suffix!r}, actual resources "
            f"{rec.get('resources')!r}"
        )
        assert rec.get("eventCategory") == "Data", (
            f"control trail {event_name}: eventCategory expected 'Data', actual "
            f"{rec.get('eventCategory')!r}"
        )

    for event_name, key in sorted(excl_wanted):
        rec = _find(excl, event_name, data_bucket, key)[0]
        assert rec.get("eventSource") == "s3.amazonaws.com", (
            f"excluding trail {event_name} {key}: eventSource {rec.get('eventSource')!r}"
        )

    # Poll through the hold rather than sleep, so a straggler landing mid-window is caught.
    hold_deadline = time.monotonic() + _HOLD_BUDGET_S
    while True:
        excl = _delivered_records(s3, log_bucket, "excl")
        leaked = _keys_under(excl, data_bucket, "excluded/")
        if leaked or time.monotonic() >= hold_deadline:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert leaked == [], (
        "the NotStartsWith exclusion must withhold every data event under excluded/: expected none "
        f"on the excluding trail, actual {leaked!r} (the control trail recorded both excluded calls "
        f"and the excluding trail delivered its later barrier {key_barrier!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
