"""snappy-and-hadoop-snappy-are-distinct-compressed-deliveries."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snappy-and-hadoop-snappy-are-distinct-compressed-deliveries"
GROUP = "delivery-format"
SERVICES = ["firehose"]

_GZIP_MAGIC = b"\x1f\x8b"
_ZIP_MAGIC = b"PK\x03\x04"

# Highly repetitive so any working compressor beats the plain bytes despite framing
# overhead; 4 x ~20 KiB stays inside the per-record and per-batch limits.
_RECORD_COUNT = 4
_FILLER = "compressible-" * 1500

_BUFFER = {"SizeInMBs": 1, "IntervalInSeconds": 60}
_DELIVERY_BUDGET_S = 300.0
_POLL_INTERVAL_S = 2.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0

_LEGS = (
    ("snappy-plain", "UNCOMPRESSED"),
    ("snappy-raw", "Snappy"),
    ("snappy-hadoop", "HADOOP_SNAPPY"),
)


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Snappy and HADOOP_SNAPPY deliveries are both smaller than an UNCOMPRESSED control, neither
    is gzip or ZIP, nothing goes to the error prefix, and the two formats yield different bytes.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"expected GetCallerIdentity to report a numeric account id, got {account!r}"
    )

    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)

    streams: dict[str, str] = {}
    for leg, compression in _LEGS:
        streams[leg] = _create_stream(ctx, bucket, role_arn, leg, compression=compression)
    for leg, compression in _LEGS:
        desc = _wait_active(ctx, streams[leg])
        reported = desc["Destinations"][0]["ExtendedS3DestinationDescription"][
            "CompressionFormat"
        ]
        assert reported == compression, (
            f"leg {leg!r} reports CompressionFormat {reported!r}, expected {compression!r}"
        )

    nonce = ctx.unique_name("sn-")
    records = [
        {"Data": f"{nonce}-record-{i:02d}-{_FILLER}\n".encode()} for i in range(_RECORD_COUNT)
    ]
    for leg, _ in _LEGS:
        resp = firehose.put_record_batch(DeliveryStreamName=streams[leg], Records=records)
        assert resp["FailedPutCount"] == 0, (
            f"PutRecordBatch on leg {leg!r} reported FailedPutCount "
            f"{resp['FailedPutCount']}, expected 0. Response: {resp['RequestResponses']!r}"
        )

    bodies: dict[str, bytes] = {}
    for leg, _ in _LEGS:
        keys = _wait_for_objects(ctx, bucket, leg + "/")
        bodies[leg] = b"".join(
            s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in keys
        )

    plain = bodies["snappy-plain"]
    raw = bodies["snappy-raw"]
    hadoop = bodies["snappy-hadoop"]

    # The control leg proves delivery works, so a compressed-leg failure is not a delivery gap.
    assert plain.count(nonce.encode()) == _RECORD_COUNT, (
        f"the UNCOMPRESSED control leg holds {plain.count(nonce.encode())} occurrences of the "
        f"run nonce {nonce!r} in {len(plain)} bytes, expected {_RECORD_COUNT}. Body begins "
        f"{plain[:200]!r}"
    )

    for leg, body in (("Snappy", raw), ("HADOOP_SNAPPY", hadoop)):
        # Snappy has no entropy coding, so the first nonce is copied literally; later repeats
        # become back-references, so the count is above zero but below the control's.
        occurrences = body.count(nonce.encode())
        assert 0 < occurrences < _RECORD_COUNT, (
            f"the {leg} leg's {len(body)} delivered bytes contain the run nonce {nonce!r} "
            f"{occurrences} time(s); the UNCOMPRESSED control leg contains it "
            f"{_RECORD_COUNT} times (once per record). A real Snappy-family encoder must "
            f"literal-copy the FIRST occurrence (nothing precedes it to back-reference) giving "
            f">= 1, and must back-reference the other {_RECORD_COUNT - 1} identical record "
            f"prefixes instead of restating them, giving < {_RECORD_COUNT}. "
            f"CompressionFormat={leg} was configured and echoed back but the occurrence count "
            f"shows no such collapse. Body begins {body[:120]!r}"
        )
        assert len(body) < len(plain), (
            f"the {leg} leg delivered {len(body)} bytes for input the UNCOMPRESSED control "
            f"leg delivered as {len(plain)} bytes; the records are "
            f"{len(_FILLER)}-byte repetitions of one token, so any working compressor must be "
            f"strictly smaller"
        )
        assert body[:2] != _GZIP_MAGIC, (
            f"the {leg} leg's delivered bytes start with the gzip magic {body[:2]!r}; "
            f"CompressionFormat={leg} must not produce gzip"
        )
        assert body[:4] != _ZIP_MAGIC, (
            f"the {leg} leg's delivered bytes start with the PKZIP signature {body[:4]!r}; "
            f"CompressionFormat={leg} must not produce a ZIP archive"
        )

    # The two enum values differ in framing, so they are not aliases.
    assert raw != hadoop, (
        f"the Snappy and HADOOP_SNAPPY legs delivered byte-identical objects "
        f"({len(raw)} bytes each, first 16 bytes {raw[:16]!r}) for identical input. The two "
        f"formats differ in framing, so they cannot produce the same stream; a target that "
        f"treats HADOOP_SNAPPY as an alias for Snappy diverges here"
    )

    for leg, _ in _LEGS:
        stray = _all_keys(ctx, bucket, leg + "-err/")
        assert stray == [], (
            f"leg {leg!r} wrote {len(stray)} objects under its ErrorOutputPrefix: {stray!r}. "
            f"Nothing in this check should fail delivery"
        )




def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-snp-")
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
    """Bounded at 40 s because all of a check's cleanups share a 60 s budget."""
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
    name = ctx.unique_name("sim2real-fh-snp-role-")
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


def _create_stream(ctx, bucket: str, role_arn: str, leg: str, *, compression: str) -> str:
    """Bounded retry past the transient InvalidArgumentException a freshly created,
    eventually consistent delivery role produces. Raises on exhaustion."""
    firehose = ctx.client("firehose")
    name = ctx.unique_name(f"sim2real-fh-{leg}-")
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
                    "Prefix": f"{leg}/",
                    "ErrorOutputPrefix": f"{leg}-err/!{{firehose:error-output-type}}/",
                    "BufferingHints": dict(_BUFFER),
                    "CompressionFormat": compression,
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
        f"CreateDeliveryStream({name!r}, CompressionFormat={compression!r}) never succeeded "
        f"within {_CREATE_BUDGET_S}s; last error {last}"
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


def _all_keys(ctx, bucket: str, prefix: str) -> list[str]:
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


def _wait_for_objects(ctx, bucket: str, prefix: str) -> list[str]:
    """Bounded poll for at least one delivered object. Raises. The wait is for a time-based
    buffer flush (IntervalInSeconds=60) that cannot be hurried."""
    left = ctx.time_left()
    end = time.monotonic() + (
        _DELIVERY_BUDGET_S if left is None else max(1.0, min(_DELIVERY_BUDGET_S, left - 5.0))
    )
    keys: list[str] = []
    while time.monotonic() < end:
        keys = _all_keys(ctx, bucket, prefix)
        if keys:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert keys, (
        f"DATAPLANE_UNIMPLEMENTED?: nothing was delivered under s3://{bucket}/{prefix} within "
        f"{_DELIVERY_BUDGET_S}s. {_RECORD_COUNT} records were put with BufferingHints "
        f"{_BUFFER!r}, so a flush is due"
    )
    return keys


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
