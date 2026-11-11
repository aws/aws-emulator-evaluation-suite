"""delivered-object-suffix-carries-the-stream-version-reported-by-describe."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delivered-object-suffix-carries-the-stream-version-reported-by-describe"
GROUP = "representation"
SERVICES = ["firehose"]

_BUFFER_INITIAL = {"SizeInMBs": 1, "IntervalInSeconds": 60}
# Changed value, so the update is a real configuration change and not a no-op echo.
_BUFFER_UPDATED = {"SizeInMBs": 2, "IntervalInSeconds": 61}
_DELIVERY_BUDGET_S = 300.0
_POLL_INTERVAL_S = 2.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0

# `<default YYYY/MM/dd/HH prefix>/<stream>-<version>-<ts>-<uuid>`
_KEY_RE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2}/\d{2})/"
    r"(?P<stream>.+)-(?P<version>\d+)-"
    r"(?P<ts>\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})-"
    r"(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """The delivered object key's version segment equals Describe's VersionId before and after an
    UpdateDestination, which must advance it; the key uses the default UTC YYYY/MM/dd/HH prefix.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/s3-object-name.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"expected GetCallerIdentity to report a numeric account id, got {account!r}"
    )

    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    stream = _create_stream(ctx, bucket, role_arn)
    desc_v1 = _wait_active(ctx, stream)

    version_1 = desc_v1["VersionId"]
    destination_id = desc_v1["Destinations"][0]["DestinationId"]
    assert isinstance(version_1, str) and version_1.isdigit(), (
        f"DescribeDeliveryStream reported VersionId {version_1!r} for a freshly created "
        f"stream; expected a decimal string"
    )

    payload_1 = f"{CHECK}|v1|{ctx.unique_name('rec-')}".encode()
    put_1_started = datetime.now(timezone.utc)
    firehose.put_record(DeliveryStreamName=stream, Record={"Data": payload_1})

    keys_after_1 = _wait_for_keys(ctx, bucket, expected=1)
    key_1 = keys_after_1[0]
    body_1 = s3.get_object(Bucket=bucket, Key=key_1)["Body"].read()
    assert payload_1 in body_1, (
        f"the first delivered object s3://{bucket}/{key_1} does not contain the record that "
        f"was put ({payload_1!r}); it holds {body_1[:200]!r}"
    )

    parsed_1 = _parse_key(key_1, stream)
    assert parsed_1["version"] == version_1, (
        f"the delivered key's version segment is {parsed_1['version']!r} but "
        f"DescribeDeliveryStream reported VersionId {version_1!r} at the time of the put. "
        f"The object-name suffix must carry the stream version, not a constant. Key: {key_1!r}"
    )
    _assert_default_time_prefix(parsed_1["date"], put_1_started)

    firehose.update_destination(
        DeliveryStreamName=stream,
        CurrentDeliveryStreamVersionId=version_1,
        DestinationId=destination_id,
        ExtendedS3DestinationUpdate={"BufferingHints": dict(_BUFFER_UPDATED)},
    )
    desc_v2 = _wait_active_with_buffering(ctx, stream, _BUFFER_UPDATED)
    version_2 = desc_v2["VersionId"]
    assert version_2.isdigit() and int(version_2) > int(version_1), (
        f"after UpdateDestination the stream reports VersionId {version_2!r}, which is not "
        f"strictly greater than the pre-update {version_1!r}. A configuration change must "
        f"advance the version"
    )

    payload_2 = f"{CHECK}|v2|{ctx.unique_name('rec-')}".encode()
    put_2_started = datetime.now(timezone.utc)
    firehose.put_record(DeliveryStreamName=stream, Record={"Data": payload_2})

    keys_after_2 = _wait_for_keys(ctx, bucket, expected=2)
    new_keys = [k for k in keys_after_2 if k != key_1]
    assert len(new_keys) == 1, (
        f"expected exactly one NEW object after the post-update put; the bucket holds "
        f"{keys_after_2!r} and the pre-update key was {key_1!r}"
    )
    key_2 = new_keys[0]
    body_2 = s3.get_object(Bucket=bucket, Key=key_2)["Body"].read()
    assert payload_2 in body_2, (
        f"the second delivered object s3://{bucket}/{key_2} does not contain the record that "
        f"was put ({payload_2!r}); it holds {body_2[:200]!r}"
    )

    parsed_2 = _parse_key(key_2, stream)
    assert parsed_2["version"] == version_2, (
        f"after the configuration change the delivered key's version segment is still "
        f"{parsed_2['version']!r} but the stream now reports VersionId {version_2!r}. An "
        f"emulator that bumps VersionId in Describe while writing a frozen version into the "
        f"object name diverges here. Key: {key_2!r}"
    )
    assert parsed_2["version"] != parsed_1["version"], (
        f"both delivered keys carry version segment {parsed_1['version']!r}; the "
        f"configuration change between them must be visible in the object name"
    )
    assert parsed_2["uuid"] != parsed_1["uuid"], (
        f"both delivered keys carry the same uuid segment {parsed_1['uuid']!r}; the suffix "
        f"uuid must be per-object"
    )
    _assert_default_time_prefix(parsed_2["date"], put_2_started)


def _parse_key(key: str, stream: str) -> dict:
    match = _KEY_RE.match(key)
    assert match is not None, (
        f"delivered key {key!r} does not match the documented default object name format "
        f"'YYYY/MM/dd/HH/<stream>-<version>-yyyy-MM-dd-HH-mm-ss-<uuid>'"
    )
    assert match.group("stream") == stream, (
        f"the delivered key's stream segment is {match.group('stream')!r}, expected the "
        f"delivery stream's own name {stream!r}. Key: {key!r}"
    )
    return match.groupdict()


def _assert_default_time_prefix(date_part: str, put_moment: datetime) -> None:
    """The default evaluated prefix is YYYY/MM/dd/HH in UTC, taken from the record's arrival
    instant. Bounded to the put hour or the next one, so an hour-boundary straddle cannot
    fail a correct target, while a stale or fabricated value still does."""
    evaluated = datetime.strptime(date_part, "%Y/%m/%d/%H").replace(tzinfo=timezone.utc)
    floor = put_moment.replace(minute=0, second=0, microsecond=0)
    allowed = {floor, floor + timedelta(hours=1)}
    assert evaluated in allowed, (
        f"the default time prefix expanded to {evaluated.isoformat()} but the record was put "
        f"at {put_moment.isoformat()}; the only admissible values are "
        f"{sorted(d.isoformat() for d in allowed)!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-ver-")
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
    """Bounded at 40 s so the remaining cleanups fit the shared 60 s cleanup budget."""
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
            time.sleep(4.0)
    raise AssertionError(f"bucket {bucket!r} could not be emptied and deleted within 40s")


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-ver-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "firehose.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
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


def _create_stream(ctx, bucket: str, role_arn: str) -> str:
    """No Prefix and no ErrorOutputPrefix: the subject is the DEFAULT object name format."""
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-ver-")
    end = time.monotonic() + _CREATE_BUDGET_S
    last = None
    while time.monotonic() < end:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                    "BufferingHints": dict(_BUFFER_INITIAL),
                    "CompressionFormat": "UNCOMPRESSED",
                },
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
            time.sleep(5.0)
    raise AssertionError(
        f"CreateDeliveryStream({name!r}) never succeeded within {_CREATE_BUDGET_S}s; last "
        f"error {last}"
    )


def _wait_active(ctx, name: str) -> dict:
    firehose = ctx.client("firehose")
    end = time.monotonic() + _ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < end:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        assert status in ("CREATING", "UPDATING"), (
            f"delivery stream {name!r} reported status {status!r} while waiting for ACTIVE"
        )
        time.sleep(4.0)
    raise AssertionError(
        f"delivery stream {name!r} never became ACTIVE within {_ACTIVE_BUDGET_S}s (last "
        f"status {status!r})"
    )


def _wait_active_with_buffering(ctx, name: str, buffering: dict) -> dict:
    """Wait for the UPDATE to be observable, not merely for ACTIVE: a stream that never left
    ACTIVE would otherwise satisfy the wait before the new configuration took effect."""
    firehose = ctx.client("firehose")
    end = time.monotonic() + _ACTIVE_BUDGET_S
    seen = None
    while time.monotonic() < end:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            described = desc["Destinations"][0]["ExtendedS3DestinationDescription"][
                "BufferingHints"
            ]
            seen = described
            if (
                described.get("SizeInMBs") == buffering["SizeInMBs"]
                and described.get("IntervalInSeconds") == buffering["IntervalInSeconds"]
            ):
                return desc
        time.sleep(4.0)
    raise AssertionError(
        f"delivery stream {name!r} never reported the updated BufferingHints "
        f"{buffering!r} within {_ACTIVE_BUDGET_S}s; last observed {seen!r}"
    )


def _all_keys(ctx, bucket: str) -> list[str]:
    s3 = ctx.client("s3")
    out: list[str] = []
    token = None
    while True:
        kwargs = {"Bucket": bucket}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        out.extend(o["Key"] for o in resp.get("Contents", []))
        if not resp.get("IsTruncated"):
            return sorted(out)
        token = resp["NextContinuationToken"]


def _wait_for_keys(ctx, bucket: str, *, expected: int) -> list[str]:
    """Bounded poll for `expected` delivered objects. Raises. The wait is for a time-based
    buffer flush (IntervalInSeconds >= 60), which cannot be hurried."""
    left = ctx.time_left()
    end = time.monotonic() + (
        _DELIVERY_BUDGET_S if left is None else max(1.0, min(_DELIVERY_BUDGET_S, left - 5.0))
    )
    keys: list[str] = []
    while time.monotonic() < end:
        keys = _all_keys(ctx, bucket)
        if len(keys) >= expected:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert len(keys) == expected, (
        f"DATAPLANE_UNIMPLEMENTED?: expected exactly {expected} delivered object(s) in "
        f"s3://{bucket} within {_DELIVERY_BUDGET_S}s, found {len(keys)}: {keys!r}. A target "
        f"that accepts PutRecord and never writes to S3 has no delivery pipeline at all"
    )
    return keys


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
