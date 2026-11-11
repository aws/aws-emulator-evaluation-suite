"""delivered-object-content-type-and-encoding-match-declared-compression."""
from __future__ import annotations

import gzip
import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delivered-object-content-type-and-encoding-match-declared-compression"
GROUP = "delivery-format"
SERVICES = ["firehose"]

_BUFFER = {"SizeInMBs": 1, "IntervalInSeconds": 60}
_CREATE_BUDGET_S = 180.0
_DELIVERY_BUDGET_S = 300.0
_POLL_INTERVAL_S = 10.0

# (leg, CompressionFormat, expected ContentEncoding, decode)
_LEGS = (
    ("ctenc-plain", "UNCOMPRESSED", None, lambda b: b),
    ("ctenc-gzip", "GZIP", "gzip", gzip.decompress),
    ("ctenc-zip", "ZIP", "zip", lambda b: zipfile.ZipFile(BytesIO(b)).read(
        zipfile.ZipFile(BytesIO(b)).namelist()[0]
    )),
)


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last observed: {last!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-ctenc-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behavioral-check", "Value": CHECK}]}
    )

    def _teardown():
        end = time.monotonic() + 30.0
        while time.monotonic() < end:
            resp = s3.list_objects_v2(Bucket=name)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            if not resp.get("IsTruncated"):
                break
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_teardown)
    return name


def _create_role(ctx, bucket):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-ctenc-role-")
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
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _try(lambda: iam.delete_role(RoleName=name)))
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
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _try(lambda: iam.delete_role_policy(RoleName=name, PolicyName="s3-write")))
    return arn


#: Error codes that mean a teardown step's resource is already gone.
_GONE = {"NoSuchEntity", "NoSuchBucket", "ResourceNotFoundException", "EntityNotFoundException"}


def _try(fn):
    """One teardown step: a resource already gone is done; any other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE:
            raise


def _create_stream(ctx, bucket, role_arn, leg, compression):
    firehose = ctx.client("firehose")
    name = ctx.unique_name(f"sim2real-behav-{leg}-")
    deadline = time.monotonic() + _CREATE_BUDGET_S
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                    "Prefix": f"{leg}/",
                    "BufferingHints": dict(_BUFFER),
                    "CompressionFormat": compression,
                },
                Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = (exc.response.get("Error", {}).get("Message") or "").lower()
            propagating = code == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _try(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)))
    return name


def _wait_active(ctx, name, timeout_s=180, interval_s=3):
    firehose = ctx.client("firehose")
    return _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"],
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"delivery stream {name} reaches ACTIVE",
    )


def _wait_for_key(ctx, bucket, prefix, timeout_s=_DELIVERY_BUDGET_S):
    s3 = ctx.client("s3")

    def _list():
        keys = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
            keys.extend(o["Key"] for o in page.get("Contents", []))
        return keys

    keys = _poll_until(
        _list,
        lambda ks: len(ks) > 0,
        timeout_s=timeout_s,
        interval_s=_POLL_INTERVAL_S,
        description=f"an object lands under {prefix!r}",
    )
    return keys[0]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Delivered objects carry ContentType application/octet-stream and ContentEncoding "gzip" for
    GZIP, "zip" for ZIP and none for UNCOMPRESSED, and each body decodes to the exact payload put.
    """
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, bucket)

    streams = {}
    for leg, compression, _enc, _decode in _LEGS:
        streams[leg] = _create_stream(ctx, bucket, role_arn, leg, compression)
    for leg, compression, _enc, _decode in _LEGS:
        desc = _wait_active(ctx, streams[leg])
        reported = desc["Destinations"][0]["ExtendedS3DestinationDescription"]["CompressionFormat"]
        assert reported == compression, (
            f"leg {leg!r} reports CompressionFormat {reported!r}, expected {compression!r}"
        )

    nonce = ctx.unique_name("ctenc-")
    payload = f"{nonce}-payload".encode("utf-8")
    firehose = ctx.client("firehose")
    for leg, _compression, _enc, _decode in _LEGS:
        resp = firehose.put_record(DeliveryStreamName=streams[leg], Record={"Data": payload})
        assert resp.get("RecordId"), f"leg {leg!r} PutRecord returned no RecordId: {resp!r}"

    s3 = ctx.client("s3")
    for leg, compression, expected_encoding, decode in _LEGS:
        key = _wait_for_key(ctx, bucket, f"{leg}/")
        obj = s3.get_object(Bucket=bucket, Key=key)
        assert obj["ContentType"] == "application/octet-stream", (
            f"leg {leg!r} (CompressionFormat={compression!r}) delivered ContentType "
            f"{obj['ContentType']!r}, expected 'application/octet-stream'"
        )
        actual_encoding = obj.get("ContentEncoding")
        assert actual_encoding == expected_encoding, (
            f"leg {leg!r} (CompressionFormat={compression!r}) delivered ContentEncoding "
            f"{actual_encoding!r}, expected {expected_encoding!r}"
        )
        body = obj["Body"].read()
        decoded = decode(body)
        assert decoded == payload, (
            f"leg {leg!r} decoded body is {decoded!r}, expected the exact payload that was put "
            f"({payload!r}); raw delivered bytes began {body[:40]!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
