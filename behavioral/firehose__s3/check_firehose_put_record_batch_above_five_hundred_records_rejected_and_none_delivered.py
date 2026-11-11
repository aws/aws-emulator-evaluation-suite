"""firehose-put-record-batch-above-five-hundred-records-rejected-and-none-delivered."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-put-record-batch-above-five-hundred-records-rejected-and-none-delivered"

GROUP = "quota"

SERVICES = ['firehose', 's3']



# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
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
    """PutRecordBatch with 501 records is rejected with ValidationException and delivers none of
    them, while a 500-record batch put into the same buffer window is accepted and all 500 markers
    are read back from S3.
    """
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    role = _firehose_role(ctx, bucket_arn=bucket_arn)
    firehose, stream = _create_stream(
        ctx, role_arn=role["arn"], bucket_arn=bucket_arn, prefix="q/"
    )

    rejected_id = ctx.unique_name("rej-")
    accepted_id = ctx.unique_name("acc-")

    def _records(batch_id: str, n: int) -> list[bytes]:
        return [
            (json.dumps({"batch": batch_id, "i": i}, sort_keys=True) + "\n").encode("utf-8")
            for i in range(n)
        ]

    too_many = _records(rejected_id, 501)
    # Capture the response instead of asserting inline: if Firehose wrongly accepts 501 records the
    # records exist, and a bare assert on the next line would abort before the absence is read.
    accepted_501 = None
    code = None
    message = ""
    try:
        accepted_501 = firehose.put_record_batch(
            DeliveryStreamName=stream, Records=[{"Data": r} for r in too_many]
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    assert accepted_501 is None, (
        f"PutRecordBatch accepted 501 records instead of rejecting them: {accepted_501!r}"
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a 501-record batch, got {code!r}: {message!r}"
    )
    want = (
        "1 validation error detected: Value at 'records' failed to satisfy constraint: "
        "Member must have length less than or equal to 500"
    )
    assert message == want, f"expected the 500-record limit message {want!r}, got {message!r}"

    ok_records = _records(accepted_id, 500)
    accepted = _put_batch_with_retry(ctx, firehose, stream, ok_records)
    assert accepted["FailedPutCount"] == 0, (
        f"the 500-record batch reported failures: {accepted!r}"
    )

    want = {f"{accepted_id}-{i}" for i in range(500)}
    seen, text = _poll_until(
        lambda: _delivered_markers(ctx, bucket, "q/"),
        lambda pair: want <= pair[0],
        timeout_s=420,
        interval_s=10,
        description="all 500 records of the accepted batch land in S3",
    )
    assert want <= seen, (
        f"delivered {len(seen & want)!r} of 500 accepted markers; "
        f"missing {sorted(want - seen)[:5]!r}"
    )
    # The accepted batch shared the rejected batch's buffer window, so its arrival proves that
    # window flushed: rejected records, had they been accepted, would be in the same objects.
    assert rejected_id not in text, (
        f"records from the rejected 501-record batch were delivered anyway; the delivered text "
        f"contains {rejected_id!r} at offset {text.find(rejected_id)!r}"
    )
    desc = firehose.describe_delivery_stream(DeliveryStreamName=stream)[
        "DeliveryStreamDescription"
    ]
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"the stream became {desc['DeliveryStreamStatus']!r} after the rejected batch"
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


def _delivered_markers(ctx, bucket: str, prefix: str) -> tuple[set[str], str]:
    """Every `<batch>-<i>` marker delivered under prefix, plus the raw concatenated text.

    The text is returned alongside the parsed set because the absence half of this check has to be
    asserted over the raw bytes, not over a parse that could silently drop a record.
    """
    s3 = ctx.client("s3")
    text = "".join(
        s3.get_object(Bucket=bucket, Key=k)["Body"].read().decode("utf-8")
        for k in sorted(_list_keys(ctx, bucket, prefix))
    )
    seen = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        seen.add(f"{rec['batch']}-{rec['i']}")
    return seen, text


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
