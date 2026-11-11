"""firehose-s3-error-prefix-on-delivery-failure."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from behavioral_harness import tags


CHECK = "firehose-s3-error-prefix-on-delivery-failure"
GROUP = "error-propagation"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A non-JSON record that fails dynamic-partitioning JQ extraction is written under
    ErrorOutputPrefix, never the partitioned Prefix, while a well-formed sibling record
    delivers normally (positive control) and never reaches the error location."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, [_s3_write_statement(bucket)])
    stream_name = ctx.unique_name("sim2real-fh-errpfx-")
    s3_config = {
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "RoleARN": role_arn,
        "Prefix": "data/customer_id=!{partitionKeyFromQuery:customer_id}/",
        "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/",
        # Firehose requires BufferingHints.SizeInMBs >= 64 when Dynamic Partitioning
        # is enabled.
        "BufferingHints": {"SizeInMBs": 64, "IntervalInSeconds": 60},
        "DynamicPartitioningConfiguration": {
            "Enabled": True,
            "RetryOptions": {"DurationInSeconds": 60},
        },
        "ProcessingConfiguration": {
            "Enabled": True,
            "Processors": [
                {
                    "Type": "MetadataExtraction",
                    "Parameters": [
                        {"ParameterName": "MetadataExtractionQuery", "ParameterValue": "{customer_id:.customer_id}"},
                        {"ParameterName": "JsonParsingEngine", "ParameterValue": "JQ-1.6"},
                    ],
                }
            ],
        },
    }
    firehose = _create_delivery_stream(ctx, stream_name, s3_config)

    good_marker = "sim2real-good-record-ok"
    bad_marker = "sim2real-malformed-not-json"
    good_record = (json.dumps({"customer_id": "good", "marker": good_marker}) + "\n").encode("utf-8")
    bad_record = (bad_marker + "\n").encode("utf-8")  # not valid JSON -> JQ extraction fails

    resp = firehose.put_record_batch(
        DeliveryStreamName=stream_name, Records=[{"Data": good_record}, {"Data": bad_record}]
    )
    assert resp["FailedPutCount"] == 0, (
        f"expected PutRecordBatch to accept both records, got FailedPutCount={resp['FailedPutCount']}"
    )

    # The IAM role's inline S3 policy was just created; its effective propagation to
    # firehose.amazonaws.com for delivery use can lag behind the role/trust becoming visible
    # (which is all _create_delivery_stream's ACTIVE-wait proves); a fresh role principal can
    # take minutes to start matching. Rather than a blind sleep, absorb that lag inside one
    # shared poll deadline for both sides: both the good and the bad record are written
    # through the same role, so they become deliverable at the same moment once permissions
    # catch up.
    good_keys, error_keys = _poll_until(
        lambda: (
            _list_keys(ctx, bucket, prefix="data/customer_id=good/"),
            _list_keys(ctx, bucket, prefix="errors/"),
        ),
        lambda pair: len(pair[0]) > 0 and len(pair[1]) > 0,
        timeout_s=260.0,
        interval_s=6.0,
    )

    good_content = b"".join(_get_bytes(ctx, bucket, k) for k in good_keys)
    error_content = b"".join(_get_bytes(ctx, bucket, k) for k in error_keys)

    assert good_marker.encode() in good_content, "well-formed record missing from its data/ prefix"
    # The failure record under ErrorOutputPrefix is wrapped in a JSON envelope
    # (errorCode/errorMessage/attemptsMade/...) with the original bytes embedded as
    # a base64 "rawData" field, not delivered verbatim -- so check both forms.
    assert _content_contains_marker(error_content, bad_marker), (
        "malformed record missing from ErrorOutputPrefix location"
    )

    # The effect must be ABSENT in the wrong location on both sides.
    assert bad_marker.encode() not in good_content, "malformed record leaked into the normal data/ prefix"
    assert not _content_contains_marker(error_content, good_marker), (
        "well-formed record leaked into the error prefix"
    )



# ===== helpers =====
from botocore.exceptions import ClientError  # noqa: E402

_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _content_contains_marker(content: bytes, marker: str) -> bool:
    """The marker may appear verbatim, or embedded as a base64-encoded "rawData"
    (or "data") field inside a per-record JSON error envelope."""
    marker_bytes = marker.encode()
    if marker_bytes in content:
        return True
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        raw = obj.get("rawData") or obj.get("data")
        if not raw:
            continue
        try:
            decoded = base64.b64decode(raw)
        except (ValueError, TypeError):
            continue
        if marker_bytes in decoded:
            return True
    return False


def _create_bucket(ctx) -> str:

    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-errpfx-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        _empty_bucket(ctx, name)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})


def _s3_write_statement(bucket: str) -> dict[str, Any]:
    return {
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


def _create_role(ctx, policy_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_FIREHOSE),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
    )

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=name, PolicyName="access")
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _wait_stream_active(firehose, name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never became ACTIVE")


def _delete_stream(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_delivery_stream(ctx, name: str, s3_config: dict[str, Any], timeout_s: float = 150.0):
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=s3_config,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"create_delivery_stream never succeeded: {last_err}")
    ctx.on_cleanup(lambda: _delete_stream(firehose, name))
    _wait_stream_active(firehose, name)
    return firehose


def _list_keys(ctx, bucket: str, prefix: str = "") -> list[str]:
    s3 = ctx.client("s3")
    keys: list[str] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _get_bytes(ctx, bucket: str, key: str) -> bytes:
    s3 = ctx.client("s3")
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def _poll_until(probe, predicate, *, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
