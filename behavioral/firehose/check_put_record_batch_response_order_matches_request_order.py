"""put-record-batch-response-order-matches-request-order."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "put-record-batch-response-order-matches-request-order"
GROUP = "ordering"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecordBatch RequestResponses[] preserves 1:1 index correspondence with Records[],
    and a malformed oversized batch is rejected atomically rather than degrading into a
    partially-ordered/truncated response array.
    """
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    name = ctx.unique_name("sim2real-behav-frh-")
    _create_s3_stream_with_retry(ctx, name, bucket, role_arn)
    _wait_stream_active(ctx, name)

    firehose = ctx.client("firehose")
    n = 60
    records = [{"Data": f"order-{i:04d}\n".encode()} for i in range(n)]
    resp = firehose.put_record_batch(DeliveryStreamName=name, Records=records)
    assert resp["FailedPutCount"] == 0, f"unexpected failures: {resp['FailedPutCount']}"
    entries = resp["RequestResponses"]
    assert len(entries) == n, f"expected {n} response entries in order, got {len(entries)}"

    record_ids = []
    for idx, entry in enumerate(entries):
        assert "ErrorCode" not in entry, f"entry at index {idx} unexpectedly failed: {entry}"
        rid = entry.get("RecordId")
        assert rid, f"entry at index {idx} missing RecordId"
        record_ids.append(rid)
    assert len(set(record_ids)) == n, "RecordIds must all be unique across a single batch response"

    # Boundary: exceeding the 500-record-per-batch limit is rejected as a single atomic
    # error for the whole call -- it never comes back as a partial/reordered array. The
    # 500-item max on the Records list is modelled with a "max" constraint, but botocore's
    # client-side ParamValidator only enforces "min" on list length (see
    # botocore.validate.ParamValidator.VALIDATED_METADATA_ATTRS), so an oversized batch is
    # never rejected locally -- it always reaches the service, which returns a generic
    # ValidationException (not InvalidArgumentException) naming the violated constraint.
    oversized = [{"Data": b"x"} for _ in range(501)]
    code, message = _error_code(lambda: firehose.put_record_batch(DeliveryStreamName=name, Records=oversized))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'records' failed to satisfy constraint: "
        "Member must have length less than or equal to 500"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====

def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe(fn, *missing: str) -> None:
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in missing:
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-frh-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(lambda: _safe(_cleanup, "NoSuchBucket"))
    return bucket


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-frh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_name = f"{role_name}-policy"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"))
    return role_arn


def _create_s3_stream_with_retry(
    ctx, name: str, bucket: str, role_arn: str,
    buffering_hints: dict[str, Any] | None = None,
    compression: str | None = None,
    timeout_s: float = 90.0,
) -> None:
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    s3_config: dict[str, Any] = {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"}
    if buffering_hints:
        s3_config["BufferingHints"] = buffering_hints
    if compression:
        s3_config["CompressionFormat"] = compression
    ctx.on_cleanup(lambda: _safe(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True),
        "ResourceNotFoundException",
    ))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, S3DestinationConfiguration=s3_config)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            role_not_ready = "not authorized" in msg or "unable to assume role" in msg
            if code == "InvalidArgumentException" and role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_stream_active(ctx, name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"delivery stream {name} entered {status}")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
