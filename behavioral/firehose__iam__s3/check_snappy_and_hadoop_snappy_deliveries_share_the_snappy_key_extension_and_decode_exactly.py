"""snappy-and-hadoop-snappy-deliveries-share-the-snappy-key-extension-and-decode-exactly."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snappy-and-hadoop-snappy-deliveries-share-the-snappy-key-extension-and-decode-exactly"
GROUP = "delivery-format"
SERVICES = ["firehose", "iam", "s3"]

_BUFFER = {"SizeInMBs": 1, "IntervalInSeconds": 60}
_DELIVERY_BUDGET_S = 300.0
_POLL_INTERVAL_S = 2.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0
_RECORD_COUNT = 5

_LEGS = (
    ("snp", "Snappy"),
    ("hsn", "HADOOP_SNAPPY"),
)
_EXPECTED_SUFFIX = ".snappy"
_SNAPPY_JAVA_MAGIC = b"\x82SNAPPY\x00"


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def _snappy_block_decompress(data: bytes) -> bytes:
    """Decode the raw Snappy block format: a varint length then literal/copy elements."""
    length, pos = _read_varint(data, 0)
    out = bytearray()
    n = len(data)
    while pos < n:
        tag = data[pos]
        pos += 1
        kind = tag & 0x3
        if kind == 0:  # literal
            upper = tag >> 2
            if upper < 60:
                lit_len = upper + 1
            else:
                nbytes = upper - 59
                lit_len = int.from_bytes(data[pos:pos + nbytes], "little") + 1
                pos += nbytes
            out += data[pos:pos + lit_len]
            pos += lit_len
        else:
            if kind == 1:  # copy, 1-byte offset
                copy_len = ((tag >> 2) & 0x7) + 4
                offset = ((tag >> 5) << 8) | data[pos]
                pos += 1
            elif kind == 2:  # copy, 2-byte offset
                copy_len = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2
            else:  # copy, 4-byte offset
                copy_len = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 4], "little")
                pos += 4
            start = len(out) - offset
            for i in range(copy_len):
                out.append(out[start + i])
    assert len(out) == length, f"decoded {len(out)} bytes, varint header declared {length}"
    return bytes(out)


def _snappy_framed_decompress(data: bytes) -> bytes:
    """Decode the stream container Firehose writes for CompressionFormat Snappy: an
    8-byte magic plus two 4-byte versions, then repeated [4-byte BE length][raw Snappy
    block], each block self-describing its own uncompressed length."""
    assert data[:8] == _SNAPPY_JAVA_MAGIC, (
        f"unexpected magic {data[:8]!r}, expected {_SNAPPY_JAVA_MAGIC!r}"
    )
    pos = 16
    n = len(data)
    out = bytearray()
    while pos < n:
        block_len = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4
        out += _snappy_block_decompress(data[pos:pos + block_len])
        pos += block_len
    return bytes(out)


def _hadoop_snappy_decompress(data: bytes) -> bytes:
    """Decode the container Firehose writes for CompressionFormat HADOOP_SNAPPY:
    [originalLen][[chunkLen][chunk]...]* repeated, each chunk a raw Snappy block,
    read until a block's declared length is produced."""
    pos = 0
    n = len(data)
    out = bytearray()
    while pos < n:
        block_len = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4
        produced = 0
        while produced < block_len:
            chunk_len = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
            piece = _snappy_block_decompress(data[pos:pos + chunk_len])
            pos += chunk_len
            out += piece
            produced += len(piece)
        assert produced == block_len, f"block declared {block_len} bytes, chunks produced {produced}"
    return bytes(out)


_DECODERS = {"Snappy": _snappy_framed_decompress, "HADOOP_SNAPPY": _hadoop_snappy_decompress}


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Snappy delivery's key and a HADOOP_SNAPPY delivery's key both end .snappy, and
    each one's bytes decode to the exact records put, each with its own container.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/s3-object-name.html
    """
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

    nonce = ctx.unique_name("fhk-")
    records = [
        {"Data": f"{nonce}-record-{i:02d}\n".encode()} for i in range(_RECORD_COUNT)
    ]
    expected_lines = sorted(r["Data"].decode().rstrip("\n") for r in records)

    for leg, _ in _LEGS:
        resp = firehose.put_record_batch(DeliveryStreamName=streams[leg], Records=records)
        assert resp["FailedPutCount"] == 0, (
            f"PutRecordBatch on leg {leg!r} reported FailedPutCount "
            f"{resp['FailedPutCount']}, expected 0. Response: {resp['RequestResponses']!r}"
        )

    for leg, compression in _LEGS:
        keys = _wait_for_objects(ctx, bucket, leg + "/")
        for key in keys:
            assert key.endswith(_EXPECTED_SUFFIX), (
                f"leg {leg!r} (CompressionFormat={compression!r}) delivered key {key!r}, "
                f"expected it to end with {_EXPECTED_SUFFIX!r}"
            )

        decoder = _DECODERS[compression]
        decoded_lines: list[str] = []
        for key in keys:
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            decoded = decoder(body)
            decoded_lines.extend(
                line for line in decoded.decode().split("\n") if line
            )
        assert sorted(decoded_lines) == expected_lines, (
            f"leg {leg!r} (CompressionFormat={compression!r}) decoded to lines "
            f"{sorted(decoded_lines)!r} across {len(keys)} object(s) {keys!r}, "
            f"expected exactly {expected_lines!r}"
        )

        stray = _all_keys(ctx, bucket, leg + "-err/")
        assert stray == [], (
            f"leg {leg!r} wrote {len(stray)} objects under its ErrorOutputPrefix: {stray!r}. "
            f"Nothing in this check should fail delivery"
        )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-sde-")
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
    name = ctx.unique_name("sim2real-fh-sde-role-")
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
