"""e2e-create-put-deliver-to-s3-delete-and-confirm-gone."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-create-put-deliver-to-s3-delete-and-confirm-gone"
GROUP = "e2e"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full flow: create stream, put records, observe them materialize as objects in the
    destination S3 bucket, delete the stream, then confirm DescribeDeliveryStream is not-found,
    the stream left ListDeliveryStreams, and PutRecord against the deleted stream is not-found."""
    bucket_name, bucket_arn = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket_arn)
    stream_name = ctx.unique_name("sim2real-behav-fh-stream-")
    prefix = "e2e/"

    _create_stream_with_retry(
        ctx,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "BucketARN": bucket_arn,
            "RoleARN": role_arn,
            "Prefix": prefix,
            "CompressionFormat": "UNCOMPRESSED",
            "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
        },
        Tags=[{"Key": "sim2real", "Value": "firehose-e2e"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stream(ctx, stream_name))
    _wait_stream_active(ctx, stream_name, timeout_s=_budget_s(ctx, 300.0))

    firehose = ctx.client("firehose")
    marker = ctx.unique_name("marker-")
    records = [{"Data": f"{marker}-{i}\n".encode()} for i in range(5)]
    resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, f"expected FailedPutCount 0, got {resp['FailedPutCount']!r}: {resp['RequestResponses']!r}"
    assert len(resp["RequestResponses"]) == 5, f"expected 5 RequestResponses, got {len(resp['RequestResponses'])}"

    lines = [f"{marker}-{i}" for i in range(5)]
    keys, body = _wait_for_lines(ctx, bucket_name, prefix, lines, timeout_s=_budget_s(ctx, 600.0))
    assert keys and all(k.startswith(prefix) for k in keys), f"delivered keys outside {prefix!r}: {keys!r}"
    delivered = body.decode().splitlines()
    missing = [ln for ln in lines if ln not in delivered]
    assert not missing, f"records {missing!r} are not lines of the delivered object(s) {keys!r}"

    firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    _wait_stream_deleted(ctx, stream_name, timeout_s=_budget_s(ctx, 300.0))

    code, msg, status = _error_code(lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx for the not-found read, got {status!r}"
    expected_message = f"Firehose under account {ctx.account} not found."
    assert msg == expected_message, f"expected the message {expected_message!r}, got {msg!r}"

    _poll_until(lambda: _stream_names(firehose), lambda names: stream_name not in names,
                timeout_s=_budget_s(ctx, 300.0), description=f"deleted stream {stream_name} leaving ListDeliveryStreams", ctx=ctx)

    code2, msg2, status2 = _error_code(
        lambda: firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": b"after-delete"})
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2!r}"
    assert isinstance(status2, int) and 400 <= status2 < 500, f"expected HTTP 4xx for PutRecord on the deleted stream, got {status2!r}"
    # The data plane answers "not active" until it, too, has dropped the stream.
    expected_messages = (
        f"Firehose not found under account {ctx.account}.",
        f"Firehose {stream_name} is not active in {ctx.account} account.",
    )
    assert msg2 in expected_messages, f"expected one of the messages {expected_messages!r}, got {msg2!r}"


def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message, HTTP status). An unexpected
    success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-fh-").lower()
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's implicit default region; passing a matching
        # LocationConstraint there is itself rejected, so it is only ever set for
        # every OTHER region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "firehose-e2e"}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    return bucket_name, f"arn:aws:s3:::{bucket_name}"


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _create_firehose_role(ctx, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "firehose-e2e"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
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
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="FirehoseS3Access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="FirehoseS3Access"))
    return role["Arn"]


def _create_stream_with_retry(ctx, **kwargs) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _safe_delete_stream(ctx, stream_name: str) -> None:
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 300.0) -> dict:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"stream {stream_name} entered CREATING_FAILED")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"stream {stream_name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_stream_deleted(ctx, stream_name: str, timeout_s: float = 300.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"stream {stream_name} leaving DescribeDeliveryStream: the run budget ended first; not graded")
    raise AssertionError(f"stream {stream_name} still describable after {timeout_s}s")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_lines(ctx, bucket: str, prefix: str, lines: list[str], timeout_s: float = 600.0):
    """Poll the prefix until every line is in the concatenated delivered objects; return
    (keys, concatenated body). Firehose may split one batch across several objects."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        keys, body = [], b""
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])
                chunk = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
                body += chunk if chunk.endswith(b"\n") or not chunk else chunk + b"\n"
        if all(ln in body.decode().splitlines() for ln in lines):
            return keys, body
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"every record line reaching prefix {prefix!r} in {bucket!r}: the run budget ended first; not graded")
    raise AssertionError(f"not every record line reached prefix {prefix!r} in {bucket!r} within {timeout_s}s")


def _poll_until(probe, predicate, *, timeout_s: float, description: str, interval_s: float = 1.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _stream_names(firehose) -> list[str]:
    """Every delivery stream name, paginated via ExclusiveStartDeliveryStreamName."""
    names: list[str] = []
    kwargs: dict = {"Limit": 100}
    while True:
        page = firehose.list_delivery_streams(**kwargs)
        names.extend(page.get("DeliveryStreamNames", []))
        if not page.get("HasMoreDeliveryStreams") or not page.get("DeliveryStreamNames"):
            return names
        kwargs["ExclusiveStartDeliveryStreamName"] = page["DeliveryStreamNames"][-1]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
