"""destination-retry-duration-respected."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "destination-retry-duration-respected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Splunk stream with RetryOptions.DurationInSeconds 0 and FailedEventsOnly backup describes those settings;
    a record sent to its unreachable HEC endpoint is not in S3 after 30 s and is backed up within a further
    420 s with a "Splunk." errorCode."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    name = ctx.unique_name("sim2real-behav-frh-")
    retry_duration = 0  # give up immediately after the first failed delivery attempt
    ack_timeout = 180  # minimum allowed acknowledgment wait
    _create_splunk_stream_with_retry(
        ctx, name, bucket, role_arn,
        hec_endpoint="https://203.0.113.7:8088/services/collector/event",  # RFC 5737 TEST-NET-3: unroutable
        retry_duration=retry_duration,
        ack_timeout=ack_timeout,
    )
    desc = _wait_stream_active(ctx, name)
    splunk_desc = desc["Destinations"][0]["SplunkDestinationDescription"]
    assert splunk_desc["RetryOptions"]["DurationInSeconds"] == retry_duration
    assert splunk_desc["HECAcknowledgmentTimeoutInSeconds"] == ack_timeout
    assert splunk_desc["S3BackupMode"] == "FailedEventsOnly"

    firehose = ctx.client("firehose")
    marker = ctx.unique_name("retrytest-")
    start = time.monotonic()
    firehose.put_record(DeliveryStreamName=name, Record={"Data": f"{marker}\n".encode()})

    # The stream sets no BufferingHints, so Splunk's documented 60 s default buffer interval passes
    # before the first delivery attempt: nothing can be backed up to S3 within 30 s.
    early_deadline = start + 30
    while time.monotonic() < early_deadline:
        time.sleep(min(5, early_deadline - time.monotonic()))
    s3 = ctx.client("s3")
    early_objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert not early_objs, f"failed record was backed up to S3 implausibly early: {early_objs}"

    # Firehose can write an unrelated permission-check object to the backup bucket, so poll for a backup record
    # whose payload holds the marker. Failed Splunk events keep the original bytes base64-encoded under
    # "rawData", so each record is decoded before the search.
    records: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []
    deadline = time.monotonic() + 420.0
    while time.monotonic() < deadline:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            content = _concat_objects(ctx, bucket, sorted(objs, key=lambda o: o["LastModified"]))
            records = _decode_backup_records(content)
            matches = [r for r in records if marker in _decoded_raw_data(r)]
            if matches:
                break
        time.sleep(2)
    if not matches:
        raise AssertionError(
            "S3 backup containing the failed Splunk record did not materialize within the bounded "
            f"poll window; decoded backup records so far: {records!r}"
        )
    backed_up = matches[0]
    error_code = backed_up.get("errorCode", "")
    assert error_code.startswith("Splunk."), (
        f"backed-up failed record missing a Splunk-specific delivery error code: {backed_up!r}"
    )


# ===== helpers =====

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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]})

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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
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


def _create_splunk_stream_with_retry(
    ctx, name: str, bucket: str, role_arn: str, hec_endpoint: str,
    retry_duration: int, ack_timeout: int, timeout_s: float = 90.0,
) -> None:
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    splunk_config: dict[str, Any] = {
        "HECEndpoint": hec_endpoint,
        "HECEndpointType": "Event",
        "HECToken": "00000000-0000-0000-0000-000000000000",
        "HECAcknowledgmentTimeoutInSeconds": ack_timeout,
        "RetryOptions": {"DurationInSeconds": retry_duration},
        "S3BackupMode": "FailedEventsOnly",
        "S3Configuration": {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"},
    }
    ctx.on_cleanup(lambda: _delete_stream_and_wait(firehose, name))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                SplunkDestinationConfiguration=splunk_config,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            role_not_ready = "not authorized" in msg or "unable to assume role" in msg
            if code == "InvalidArgumentException" and role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


#: Bound for a deleted delivery stream to answer not-found, inside the suite's cleanup budget.
_STREAM_DELETE_S = 300.0


def _delete_stream_and_wait(firehose, name: str) -> None:
    """Delete the stream and poll every 2 s until it is gone, so no late backup flush lands after the bucket is emptied."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _STREAM_DELETE_S
    deleted = False
    while True:
        status = None
        try:
            if not deleted:
                firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
                deleted = True
            status = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
                "DeliveryStreamStatus"
            ]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
        if status == "DELETING_FAILED":
            raise AssertionError(f"delivery stream {name} entered DELETING_FAILED")
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present {_STREAM_DELETE_S:.0f} s after DeleteDeliveryStream")
        time.sleep(2)


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


def _poll_s3_objects(ctx, bucket: str, prefix: str = "", min_count: int = 1,
                      timeout_s: float = 180.0, interval_s: float = 5.0) -> list[dict[str, Any]]:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    objs: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        objs = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
        if len(objs) >= min_count:
            break
        time.sleep(interval_s)
    return sorted(objs, key=lambda o: o["LastModified"])


def _concat_objects(ctx, bucket: str, objs: list[dict[str, Any]]) -> str:
    s3 = ctx.client("s3")
    parts = []
    for o in objs:
        body = s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read()
        parts.append(body.decode("utf-8"))
    return "".join(parts)


def _decode_backup_records(content: str) -> list[dict[str, Any]]:
    """Firehose writes one JSON record per line to the S3 backup object."""
    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _decoded_raw_data(record: dict[str, Any]) -> str:
    raw = record.get("rawData")
    if not raw:
        return ""
    try:
        return base64.b64decode(raw).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return ""


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
