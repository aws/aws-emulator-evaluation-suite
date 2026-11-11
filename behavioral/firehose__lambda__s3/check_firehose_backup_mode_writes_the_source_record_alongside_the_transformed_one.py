"""firehose-backup-mode-writes-the-source-record-alongside-the-transformed-one."""

from __future__ import annotations

import base64
import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-backup-mode-writes-the-source-record-alongside-the-transformed-one"

GROUP = "transformation"

SERVICES = ['firehose', 'lambda', 's3']



_TRANSFORM = """
    import base64


    def lambda_handler(event, context):
        out = []
        for rec in event["records"]:
            raw = base64.b64decode(rec["data"])
            out.append(
                {
                    "recordId": rec["recordId"],
                    "result": "Ok",
                    "data": base64.b64encode(raw[::-1] + b"\\n").decode("utf-8"),
                }
            )
        return {"records": out}
"""


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """With S3BackupMode=Enabled one PutRecord produces two S3 objects: the transformed record under
    the main prefix and the untransformed source record under the backup prefix, with differing
    bodies; only the delivered objects reveal whether source backup is honored."""
    bucket = _new_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    fn = _create_transform_lambda(ctx, _TRANSFORM)
    role = _firehose_role(
        ctx,
        bucket_arn=bucket_arn,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": ["lambda:InvokeFunction", "lambda:GetFunctionConfiguration"],
                "Resource": [fn["arn"], f"{fn['arn']}:*"],
            }
        ],
    )
    firehose, stream = _create_stream(
        ctx,
        role_arn=role["arn"],
        bucket_arn=bucket_arn,
        prefix="main/",
        extra={
            "ProcessingConfiguration": {
                "Enabled": True,
                "Processors": [_lambda_processor(fn["arn"])],
            },
            "S3BackupMode": "Enabled",
            "S3BackupConfiguration": {
                "RoleARN": role["arn"],
                "BucketARN": bucket_arn,
                "Prefix": "backup/",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                "CompressionFormat": "UNCOMPRESSED",
            },
        },
    )

    payload = ctx.unique_name("bkp-").encode("utf-8") + b"-ZZZ"
    _put_record_with_retry(ctx, firehose, stream, payload)

    main_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "main/"),
        lambda ks: len(ks) > 0,
        timeout_s=420,
        interval_s=10,
        description="the transformed record lands under main/",
    )
    backup_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, "backup/"),
        lambda ks: len(ks) > 0,
        timeout_s=300,
        interval_s=10,
        description="the source record lands under backup/",
    )
    assert (len(main_keys), len(backup_keys)) == (1, 1), (
        f"expected one object per prefix, got main={sorted(main_keys)!r} "
        f"backup={sorted(backup_keys)!r}"
    )
    s3 = ctx.client("s3")
    main_body = s3.get_object(Bucket=bucket, Key=main_keys[0])["Body"].read()
    backup_body = s3.get_object(Bucket=bucket, Key=backup_keys[0])["Body"].read()

    assert main_body.rstrip(b"\n") == payload[::-1], (
        f"main/ held {main_body[:120]!r}, expected the reversed payload {payload[::-1]!r}"
    )
    assert backup_body == payload, (
        f"backup/ held {backup_body[:120]!r}, expected the untransformed source {payload!r}"
    )
    assert main_body.rstrip(b"\n") != backup_body, (
        f"both prefixes held {main_body[:120]!r}, so source backup is indistinguishable from "
        f"the transformed delivery"
    )
    described = firehose.describe_delivery_stream(DeliveryStreamName=stream)[
        "DeliveryStreamDescription"
    ]["Destinations"][0]["ExtendedS3DestinationDescription"]
    assert described["S3BackupMode"] == "Enabled", (
        f"S3BackupMode was described as {described.get('S3BackupMode')!r}"
    )
    assert described["S3BackupDescription"]["Prefix"] == "backup/", (
        f"the described backup prefix was {described['S3BackupDescription'].get('Prefix')!r}"
    )


# ===== helpers =====
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


_TEARDOWN_GONE = ("NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException", "EntityNotFoundException")
_TEARDOWN_BUSY = (
    "ResourceInUseException", "ResourceConflictException", "ConcurrentModificationException",
    "DeleteConflict", "OperationAbortedException", "ThrottlingException", "Throttling",
    "TooManyRequestsException",
)


def _retry_teardown(fn, *, deadline_s=60.0) -> None:
    """Run a teardown delete: return when done or already gone, retry a busy or throttled
    refusal every 2 s up to deadline_s, raise everything else."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _TEARDOWN_GONE:
                return
            if code not in _TEARDOWN_BUSY or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _delete_stream_and_wait(ctx, name: str, timeout_s: float = 300.0) -> None:
    """Delete the stream and poll every 2 s until it is gone: DeleteDeliveryStream returns while
    the stream is still DELETING, and a still-listed stream is a leak. Raises at the deadline."""
    firehose = ctx.client("firehose")
    _retry_teardown(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") in _TEARDOWN_GONE:
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present {timeout_s}s after DeleteDeliveryStream")
        time.sleep(2)


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
    ctx.on_cleanup(lambda: _delete_stream_and_wait(ctx, name))
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


def _wait_function_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} reaches Active",
    )


def _create_transform_lambda(ctx, handler_code: str) -> dict[str, str]:
    """Create a tagged Firehose transform Lambda (logs-only execution role) and wait until Active.

    The handler source is dedented and zipped in-memory; no build step and no S3 asset. Both the
    function and the log group Lambda mints on first invoke get a teardown, registered immediately.
    """
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:*:*:*",
                }
            ],
        },
        "role-lambda",
    )
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role["arn"],
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": buf.getvalue()},
        Timeout=60,
        MemorySize=256,
        Tags=dict(_xsvc_resource_tags()),
    )
    deadline = time.monotonic() + 120
    while True:
        try:
            resp = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            # A role created seconds ago cannot yet be assumed by Lambda; bounded retry, not sleep.
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(
        lambda: _retry_teardown(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    )
    ctx.on_cleanup(
        lambda: _retry_teardown(
            lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
        )
    )
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"]}


def _lambda_processor(fn_arn: str) -> dict[str, Any]:
    """The ProcessingConfiguration processor entry that wires a transform Lambda into delivery."""
    return {
        "Type": "Lambda",
        "Parameters": [
            {"ParameterName": "LambdaArn", "ParameterValue": fn_arn},
            {"ParameterName": "NumberOfRetries", "ParameterValue": "1"},
            {"ParameterName": "BufferSizeInMBs", "ParameterValue": "1"},
            {"ParameterName": "BufferIntervalInSeconds", "ParameterValue": "60"},
        ],
    }


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
