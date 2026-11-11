"""custom-time-zone-shifts-the-timestamp-prefix-expansion."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-time-zone-shifts-the-timestamp-prefix-expansion"
GROUP = "data-plane"
SERVICES = ["firehose"]

# Asia/Tokyo is UTC+09:00 year round (no DST), so the expected delta is a fixed constant.
_ZONE = "Asia/Tokyo"
_ZONE_OFFSET = timedelta(hours=9)

# Zero buffering interval: each record is delivered as soon as it arrives.
_BUFFER = {"SizeInMBs": 1, "IntervalInSeconds": 0}
# The object-name suffix is stamped when the object is written; S3 LastModified lands within this.
_SUFFIX_SLACK = timedelta(minutes=2)
# Deliberately generous: S3 delivery has been seen to take well over 200 s.
_DELIVERY_BUDGET_S = 300.0
_POLL_INTERVAL_S = 1.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0

# `d=`/`h=` style so the key parses unambiguously; distinct top-level prefixes isolate the legs.
_PREFIX_TMPL = "{leg}/d=!{{timestamp:yyyy-MM-dd}}/h=!{{timestamp:HH}}/"
_ERROR_PREFIX_TMPL = "{leg}-err/!{{firehose:error-output-type}}/"

_PREFIX_RE = re.compile(r"^(?P<leg>[^/]+)/d=(?P<date>\d{4}-\d{2}-\d{2})/h=(?P<hour>\d{2})/")
# <evaluated prefix><stream name>-<stream version>-yyyy-MM-dd-HH-mm-ss-<uuid><ext>
_SUFFIX_RE = re.compile(
    r"-(?P<version>\d+)-(?P<ts>\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})-"
    r"[0-9a-fA-F-]{36}$"
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CustomTimeZone=Asia/Tokyo shifts the expanded timestamp prefix by exactly +9 h relative to
    a UTC-default stream and the object-name suffix by +9 h from UTC, and Describe echoes the zone.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"expected GetCallerIdentity to report a numeric account id, got {account!r}"
    )

    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)

    control_leg = "tz-utc"
    treated_leg = "tz-tokyo"
    control = _create_stream(ctx, bucket, role_arn, control_leg, custom_time_zone=None)
    treated = _create_stream(ctx, bucket, role_arn, treated_leg, custom_time_zone=_ZONE)

    control_desc = _wait_active(ctx, control)
    treated_desc = _wait_active(ctx, treated)

    # The echo rules out "the field was dropped on the way in" as the cause of a digit failure.
    treated_cfg = treated_desc["Destinations"][0]["ExtendedS3DestinationDescription"]
    control_cfg = control_desc["Destinations"][0]["ExtendedS3DestinationDescription"]
    assert treated_cfg.get("CustomTimeZone") == _ZONE, (
        f"the treated stream reports CustomTimeZone "
        f"{treated_cfg.get('CustomTimeZone')!r}, expected {_ZONE!r} -- it was set at "
        f"CreateDeliveryStream and must be echoed back"
    )
    assert control_cfg.get("CustomTimeZone", "") in ("", None), (
        f"the control stream reports CustomTimeZone "
        f"{control_cfg.get('CustomTimeZone')!r}; no CustomTimeZone was supplied for it, so "
        f"it must come back absent or empty for the +9 h comparison to mean anything"
    )

    # The timestamp namespace uses each record's arrival instant, so each leg's hour is one of the
    # hours the put window touches.
    payload = f"{CHECK}|{ctx.unique_name('rec-')}".encode()
    put_started = datetime.now(timezone.utc)
    firehose.put_record(DeliveryStreamName=control, Record={"Data": payload})
    firehose.put_record(DeliveryStreamName=treated, Record={"Data": payload})
    put_finished = datetime.now(timezone.utc)

    control_key = _wait_for_one_object(ctx, bucket, control_leg + "/")
    treated_key = _wait_for_one_object(ctx, bucket, treated_leg + "/")

    for leg, key in (("control", control_key), ("treated", treated_key)):
        assert "!{" not in key, (
            f"the {leg} leg's delivered key still contains an unexpanded namespace token: "
            f"{key!r} -- the prefix expression was stored verbatim instead of evaluated"
        )
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert payload in body, (
            f"the {leg} leg's object s3://{bucket}/{key} does not contain the record that was "
            f"put ({payload!r}); it holds {body[:200]!r}. The key was parsed from an object "
            f"this check did not produce"
        )

    control_dt = _prefix_datetime(control_key, control_leg)
    treated_dt = _prefix_datetime(treated_key, treated_leg)

    allowed_control = {_floor_hour(put_started), _floor_hour(put_finished)}
    delta = treated_dt - control_dt
    same_hour = len(allowed_control) == 1
    # The treated record is put after the control one, so its UTC hour is never before the control's.
    treated_utc = treated_dt - _ZONE_OFFSET
    straddle_ok = treated_utc in allowed_control and treated_utc >= control_dt
    assert (delta == _ZONE_OFFSET) if same_hour else straddle_ok, (
        f"CustomTimeZone={_ZONE!r} did not shift the expanded timestamp prefix: the "
        f"UTC-default leg expanded to {control_dt.isoformat()} (key {control_key!r}) and the "
        f"Asia/Tokyo leg to {treated_dt.isoformat()} (key {treated_key!r}), a delta of "
        f"{delta}, expected exactly {_ZONE_OFFSET} (Asia/Tokyo is UTC+09:00 with no DST) from "
        f"an arrival hour in {sorted(d.isoformat() for d in allowed_control)!r}"
    )

    # The control digits must be the real arrival hour, not a constant 9 h behind the treated one.
    assert control_dt in allowed_control, (
        f"the UTC-default leg expanded to {control_dt.isoformat()}, which is not the hour the "
        f"record actually arrived in: the put window was "
        f"[{put_started.isoformat()}, {put_finished.isoformat()}], so the only admissible "
        f"values are {sorted(d.isoformat() for d in allowed_control)!r}"
    )

    # Each suffix is read against its own object's UTC write time, so the two legs' independent
    # flush instants do not enter the comparison.
    for leg, key, offset in (("control", control_key, timedelta(0)),
                             ("treated", treated_key, _ZONE_OFFSET)):
        suffix = _suffix_datetime(key)
        written = s3.head_object(Bucket=bucket, Key=key)["LastModified"].astimezone(timezone.utc)
        drift = abs(suffix - offset - written)
        assert drift <= _SUFFIX_SLACK, (
            f"CustomTimeZone={_ZONE!r}: the {leg} leg's object-name suffix {suffix.isoformat()} "
            f"(key {key!r}) is not its UTC write time {written.isoformat()} shifted by {offset}; "
            f"it is off by {drift}, expected within {_SUFFIX_SLACK}"
        )

    # A record diverted to `*-err/` could otherwise look identical above.
    for leg in (control_leg, treated_leg):
        stray = _all_keys(ctx, bucket, leg + "-err/")
        assert stray == [], (
            f"delivery stream leg {leg!r} wrote {len(stray)} objects under its "
            f"ErrorOutputPrefix {leg + '-err/'!r}: {stray!r}. Nothing in this check should "
            f"fail delivery"
        )


def _floor_hour(moment: datetime) -> datetime:
    return moment.replace(minute=0, second=0, microsecond=0)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _prefix_datetime(key: str, expected_leg: str) -> datetime:
    match = _PREFIX_RE.match(key)
    assert match is not None, (
        f"delivered key {key!r} does not match the expanded prefix shape "
        f"'<leg>/d=YYYY-MM-DD/h=HH/'; the !{{timestamp:...}} expressions were not expanded "
        f"into date/time digits"
    )
    assert match.group("leg") == expected_leg, (
        f"delivered key {key!r} is under leg {match.group('leg')!r}, expected "
        f"{expected_leg!r}"
    )
    return datetime.strptime(
        f"{match.group('date')} {match.group('hour')}", "%Y-%m-%d %H"
    ).replace(tzinfo=timezone.utc)


def _suffix_datetime(key: str) -> datetime:
    match = _SUFFIX_RE.search(key)
    assert match is not None, (
        f"delivered key {key!r} does not carry the documented object-name suffix "
        f"'<stream>-<version>-yyyy-MM-dd-HH-mm-ss-<uuid>'; got the tail "
        f"{key[-80:]!r}"
    )
    return datetime.strptime(match.group("ts"), "%Y-%m-%d-%H-%M-%S").replace(
        tzinfo=timezone.utc
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-tz-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Firehose can still be flushing at cleanup, so empty in a loop and retry BucketNotEmpty.
    Capped at 40 s so the remaining cleanups fit the shared 60 s cleanup budget."""
    s3 = ctx.client("s3")
    end = time.monotonic() + 40.0
    while time.monotonic() < end:
        token = None
        while True:
            kwargs = {"Bucket": bucket}
            if token:
                kwargs["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kwargs)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            if not resp.get("IsTruncated"):
                break
            token = resp["NextContinuationToken"]
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "BucketNotEmpty":
                raise
            time.sleep(2.0)
    raise AssertionError(f"bucket {bucket!r} could not be emptied and deleted within 40s")


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-tz-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description=f"sim2real-behav {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="s3-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:AbortMultipartUpload",
                            "s3:GetBucketLocation",
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:ListBucketMultipartUploads",
                            "s3:PutObject",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket}",
                            f"arn:aws:s3:::{bucket}/*",
                        ],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="s3-write"))
    return arn


def _create_stream(ctx, bucket: str, role_arn: str, leg: str, *, custom_time_zone) -> str:
    """Create the stream, retrying InvalidArgumentException while the new role propagates.
    Firehose assumes the delivery role at create time, and IAM is eventually consistent."""
    firehose = ctx.client("firehose")
    name = ctx.unique_name(f"sim2real-fh-{leg}-")
    dest = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": _PREFIX_TMPL.format(leg=leg),
        "ErrorOutputPrefix": _ERROR_PREFIX_TMPL.format(leg=leg),
        "BufferingHints": dict(_BUFFER),
        "CompressionFormat": "UNCOMPRESSED",
    }
    if custom_time_zone is not None:
        dest["CustomTimeZone"] = custom_time_zone

    create_budget = _budget_s(ctx, _CREATE_BUDGET_S)
    end = time.monotonic() + create_budget
    last = None
    while time.monotonic() < end:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(
                lambda n=name: firehose.delete_delivery_stream(
                    DeliveryStreamName=n, AllowForceDelete=True
                )
            )
            return name
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"CreateDeliveryStream({name!r}) succeeding: the run budget ended first; not graded")
    raise AssertionError(
        f"CreateDeliveryStream({name!r}) never succeeded within {create_budget:.0f}s; last "
        f"error {last}"
    )


def _wait_active(ctx, name: str) -> dict:
    firehose = ctx.client("firehose")
    active_budget = _budget_s(ctx, _ACTIVE_BUDGET_S)
    end = time.monotonic() + active_budget
    status = None
    while time.monotonic() < end:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        assert status in ("CREATING", "UPDATING"), (
            f"delivery stream {name!r} reported status {status!r} while waiting for ACTIVE; "
            f"CREATING/UPDATING are the only admissible transients"
        )
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"delivery stream {name!r} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(
        f"delivery stream {name!r} never became ACTIVE within {active_budget:.0f}s (last "
        f"status {status!r})"
    )


def _all_keys(ctx, bucket: str, prefix: str) -> list[str]:
    """Every key under prefix, across all pages."""
    s3 = ctx.client("s3")
    out: list[str] = []
    token = None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        out.extend(o["Key"] for o in resp.get("Contents", []))
        if not resp.get("IsTruncated"):
            return sorted(out)
        token = resp["NextContinuationToken"]


def _wait_for_one_object(ctx, bucket: str, prefix: str) -> str:
    """Bounded poll for exactly one delivered object under prefix; raises on timeout."""
    delivery_budget = _budget_s(ctx, _DELIVERY_BUDGET_S)
    end = time.monotonic() + delivery_budget
    keys: list[str] = []
    while time.monotonic() < end:
        keys = _all_keys(ctx, bucket, prefix)
        if keys:
            break
        time.sleep(_POLL_INTERVAL_S)
    if not keys and _budget_spent(ctx):
        raise TimeoutError(f"a delivered object under s3://{bucket}/{prefix}: the run budget ended first; not graded")
    assert len(keys) == 1, (
        f"DATAPLANE_UNIMPLEMENTED?: expected exactly 1 delivered object under "
        f"s3://{bucket}/{prefix} within {delivery_budget:.0f}s, found {len(keys)}: {keys!r}. "
        f"One record was put with BufferingHints {_BUFFER!r}, so one flush is due; a target "
        f"that accepts PutRecord and never writes to S3 has no delivery pipeline at all"
    )
    return keys[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
