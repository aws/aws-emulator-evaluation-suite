"""put-record-batch-empty-records-list-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-empty-records-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The service itself rejects PutRecordBatch with an empty Records list with
    ValidationException; a non-empty batch on the same stream is fully accepted."""
    firehose = ctx.client("firehose")
    # botocore enforces Records length(min=1) locally; disable that so the service must refuse.
    unvalidated = ctx.client("firehose", config=Config(parameter_validation=False))
    bucket_arn, role_arn = _bucket_and_role(ctx)

    stream_name = ctx.unique_name("sim2real-fh-batch-")
    _create_stream_retrying(
        firehose,
        DeliveryStreamName=stream_name,
        ExtendedS3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
    )
    ctx.on_cleanup(lambda: _force_delete_stream(firehose, stream_name))
    _wait_stream_active(firehose, stream_name, timeout_s=120)

    code = msg = None
    try:
        unvalidated.put_record_batch(DeliveryStreamName=stream_name, Records=[])
    except ClientError as err:
        code = err.response["Error"]["Code"]
        msg = err.response["Error"].get("Message")

    assert code == "ValidationException", (
        f"expected ValidationException for an empty Records list sent to the service, got {code!r}"
    )
    expected_msg = (
        "1 validation error detected: Value at 'records' failed to satisfy constraint: "
        "Member must have length greater than or equal to 1"
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # positive control: a real non-empty batch on the same stream is fully accepted
    records = [{"Data": f"record-{i}\n".encode()} for i in range(5)]
    resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, f"expected 0 failed puts, got {resp['FailedPutCount']}"
    assert len(resp["RequestResponses"]) == 5, (
        f"expected 5 response entries, got {len(resp['RequestResponses'])}"
    )
    for entry in resp["RequestResponses"]:
        assert "ErrorCode" not in entry, f"unexpected per-record error: {entry}"
        assert entry["RecordId"]


def _bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-fh-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    role_name = ctx.unique_name("sim2real-fh-role-")
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-s3-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return bucket_arn, role_arn


def _create_stream_retrying(firehose, *, timeout_s: float = 90, interval_s: float = 5, **kwargs: Any):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidArgumentException" and (
                "not authorized" in msg or "Access Denied" in msg or "assume" in msg.lower()
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None
    raise last_err


def _wait_stream_active(firehose, name: str, timeout_s: float = 120) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never reached ACTIVE (last status={status})")


def _force_delete_stream(firehose, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
