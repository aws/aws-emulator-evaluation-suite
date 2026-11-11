"""firehose-record-above-the-per-record-ceiling-rejected-while-a-just-under-record-delivers."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-record-above-the-per-record-ceiling-rejected-while-a-just-under-record-delivers"

GROUP = "quota"

SERVICES = ['firehose', 's3']



#: Firehose's documented per-record ceiling before base64 encoding is 1000 KiB, not 1 MiB.
_RECORD_LIMIT_BYTES = 1000 * 1024


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A PutRecord one byte over the 1000 KiB per-record ceiling is rejected with ValidationException
    and never delivered, while a payload one byte under it is delivered to S3 byte for byte in the
    same buffer window.
    """
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    role = _firehose_role(ctx, bucket_arn=bucket_arn)
    firehose, stream = _create_stream(
        ctx, role_arn=role["arn"], bucket_arn=bucket_arn, prefix="sz/"
    )

    big_marker = ctx.unique_name("big-")
    ok_marker = ctx.unique_name("ok-")
    too_big = _sized_payload(big_marker, _RECORD_LIMIT_BYTES + 1)
    ok_payload = _sized_payload(ok_marker, _RECORD_LIMIT_BYTES - 1)

    # Capture rather than assert inline: an oversized record wrongly accepted gets delivered, and
    # the absence read below is the only place that becomes visible.
    accepted_big = None
    code = None
    message = ""
    try:
        accepted_big = firehose.put_record(DeliveryStreamName=stream, Record={"Data": too_big})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    assert accepted_big is None, (
        f"PutRecord accepted a {len(too_big)!r}-byte record: {accepted_big!r}"
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a {len(too_big)!r}-byte record, "
        f"got {code!r}: {message!r}"
    )
    want = (
        "1 validation error detected: Value at 'record.data' failed to satisfy constraint: "
        f"Member must have length less than or equal to {_RECORD_LIMIT_BYTES}"
    )
    assert message == want, f"expected the per-record limit message {want!r}, got {message!r}"

    put = _put_record_with_retry(ctx, firehose, stream, ok_payload)
    assert put.get("RecordId"), f"the under-limit PutRecord returned no RecordId: {put!r}"

    keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "sz/"),
        lambda ks: len(ks) > 0,
        timeout_s=420,
        interval_s=10,
        description="the under-limit record lands in S3",
    )
    s3 = ctx.client("s3")
    all_delivered = b"".join(
        s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in sorted(keys)
    )
    # Both payloads were put in the same buffer window, so the under-limit record's arrival proves
    # that window flushed.
    assert big_marker.encode() not in all_delivered, (
        f"the oversized record was delivered: {big_marker!r} found in "
        f"{len(all_delivered)!r} delivered bytes"
    )
    assert ok_marker.encode() in all_delivered, (
        f"the {len(ok_payload)!r}-byte record was not delivered; got "
        f"{len(all_delivered)!r} bytes under sz/"
    )
    assert all_delivered == ok_payload, (
        f"delivered {len(all_delivered)!r} bytes, expected exactly the {len(ok_payload)!r} that "
        f"were put; first differing offset "
        f"{next((i for i, (a, b) in enumerate(zip(all_delivered, ok_payload)) if a != b), None)!r}"
    )
    desc = firehose.describe_delivery_stream(DeliveryStreamName=stream)[
        "DeliveryStreamDescription"
    ]
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"the stream became {desc['DeliveryStreamStatus']!r} after an oversized put"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

_S3_DELIVERY_ACTIONS = [
    "s3:AbortMultipartUpload",
    "s3:GetBucketLocation",
    "s3:GetObject",
    "s3:ListBucket",
    "s3:ListBucketMultipartUploads",
    "s3:PutObject",
]


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_bucket(ctx, bucket: str) -> None:
    """Empty a bucket (objects + versions + delete markers) then delete it. Teardown swallows
    exceptions, so a raw delete_bucket on a non-empty bucket would silently leak it."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    _retry_teardown(lambda: s3.delete_bucket(Bucket=bucket))


def _retry_teardown(fn, *, attempts=4, interval_s=3.0) -> None:
    """Retry a teardown call; not-found means gone and the last failure raises."""
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException"):
                return
            if i == attempts - 1:
                raise
            time.sleep(interval_s)


def _new_bucket(ctx, kind: str = "bkt") -> str:
    """Create a uniquely-named, region-correct, tagged bucket; register empty+delete teardown."""
    s3 = ctx.client("s3")
    name = _xname(ctx, kind)
    params: dict[str, Any] = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return name


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    _retry_teardown(lambda: iam.delete_role(RoleName=role_name))


def _create_role(ctx, trust_service: str, inline_policy: dict, kind: str) -> dict[str, str]:
    """Create a tagged IAM role under /sim2real/ and register its teardown immediately."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, kind)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _firehose_role(ctx, *, bucket_arn, extra_statements=None) -> dict[str, str]:
    """The Firehose delivery role: S3 write on one bucket, plus whatever the destination needs."""
    statements = [
        {
            "Effect": "Allow",
            "Action": _S3_DELIVERY_ACTIONS,
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }
    ]
    statements.extend(extra_statements or [])
    return _create_role(
        ctx,
        "firehose.amazonaws.com",
        {"Version": "2012-10-17", "Statement": statements},
        "role-firehose",
    )


def _create_stream(ctx, *, role_arn, bucket_arn, prefix, extra=None, error_prefix=None):
    """Create a DirectPut -> ExtendedS3 delivery stream and poll it to ACTIVE.

    Firehose ASSUMES the delivery role during CreateDeliveryStream, so a role created seconds ago
    loses the IAM propagation race with `InvalidArgumentException: ... unable to assume role`.
    That window is retried against a deadline rather than slept through.
    """
    firehose = ctx.client("firehose")
    name = _xname(ctx, "dstream")
    dest: dict[str, Any] = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "Prefix": prefix,
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CompressionFormat": "UNCOMPRESSED",
    }
    if error_prefix is not None:
        dest["ErrorOutputPrefix"] = error_prefix
    dest.update(extra or {})
    kwargs = dict(
        DeliveryStreamName=name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration=dest,
        Tags=_xsvc_tags_kv(),
    )
    deadline = time.monotonic() + 120
    while True:
        try:
            firehose.create_delivery_stream(**kwargs)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if (
                code == "InvalidArgumentException"
                and ("assume role" in msg.lower() or "not authorized" in msg.lower())
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(
        lambda: _retry_teardown(
            lambda: ctx.client("firehose").delete_delivery_stream(DeliveryStreamName=name)
        )
    )
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s in ("ACTIVE", "CREATING_FAILED"),
        timeout_s=300,
        interval_s=5,
        description=f"delivery stream {name} reaches ACTIVE",
    )
    assert status == "ACTIVE", f"delivery stream {name} became {status!r} instead of ACTIVE"
    return firehose, name


def _put_batch_with_retry(ctx, firehose, stream, records, *, timeout_s=180.0):
    """PutRecordBatch, retrying only the delivery-role propagation window at first use.

    A brand-new stream can reject the first put while the role it assumed is still converging.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.put_record_batch(
                DeliveryStreamName=stream, Records=[{"Data": r} for r in records]
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in (
                "AccessDeniedException",
                "AccessDenied",
                "ServiceUnavailableException",
                "ResourceNotFoundException",
            ) and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _list_keys(ctx, bucket: str, prefix: str) -> list[str]:
    """Every key under prefix, across all pages."""
    s3 = ctx.client("s3")
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _sized_payload(marker: str, size: int) -> bytes:
    """A deterministic payload of exactly `size` bytes: `<marker>:` + filler + a trailing newline."""
    head = f"{marker}:".encode("utf-8")
    filler = bytes((i * 7 + 11) % 251 + 1 for i in range(size - len(head) - 1))
    out = head + filler + b"\n"
    assert len(out) == size, f"payload is {len(out)!r} bytes, wanted {size!r}"
    return out


def _put_record_with_retry(ctx, firehose, stream, data: bytes, *, timeout_s=180.0):
    """PutRecord, retrying only the delivery-role propagation window at first use of the role."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.put_record(DeliveryStreamName=stream, Record={"Data": data})
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in (
                "AccessDeniedException",
                "ServiceUnavailableException",
                "ResourceNotFoundException",
            ) and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
