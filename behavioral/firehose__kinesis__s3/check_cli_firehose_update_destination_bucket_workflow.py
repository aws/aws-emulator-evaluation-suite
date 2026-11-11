"""cli-firehose-update-destination-bucket-workflow."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-firehose-update-destination-bucket-workflow"
GROUP = "cli-script"
SERVICES = ["firehose", "kinesis", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CLI update-destination that switches a Firehose delivery stream's S3 bucket causes
    subsequent records to be delivered to the new bucket (and not the old one)."""
    require_tools("aws")

    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket1 = _create_bucket(ctx)
    bucket2 = _create_bucket(ctx)
    bucket1_arn = f"arn:aws:s3:::{bucket1}"
    bucket2_arn = f"arn:aws:s3:::{bucket2}"

    role_arn = _create_firehose_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
                "Resource": [bucket1_arn, f"{bucket1_arn}/*", bucket2_arn, f"{bucket2_arn}/*"],
            }
        ],
    )

    delivery_stream_name = ctx.unique_name("sim2real-fh-ds-")
    s3_dest_config1 = json.dumps(
        {"RoleARN": role_arn, "BucketARN": bucket1_arn, "Prefix": "records/", "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60}}
    )
    _create_delivery_stream_with_retry(
        ctx,
        [
            "--delivery-stream-name", delivery_stream_name,
            "--delivery-stream-type", "DirectPut",
            "--extended-s3-destination-configuration", s3_dest_config1,
            "--tags", json.dumps([{"Key": "sim2real", "Value": CHECK}]),
        ],
    )
    ctx.on_cleanup(
        lambda: _run_shell(ctx, ["aws", "firehose", "delete-delivery-stream", "--delivery-stream-name", delivery_stream_name], check=False)
    )
    desc = _wait_delivery_stream_active(ctx, delivery_stream_name)
    destination_id = desc["Destinations"][0]["DestinationId"]
    version_id = desc["VersionId"]

    marker1 = ctx.unique_name("first-")
    firehose.put_record(DeliveryStreamName=delivery_stream_name, Record={"Data": f"first-{marker1}\n".encode()})
    contents1 = _poll_s3_prefix(ctx, bucket1, "records/", timeout_s=200.0, interval_s=5.0)
    assert contents1, "record was never delivered to the initial (bucket1) destination"
    assert _bucket_contains_marker(ctx, bucket1, contents1, marker1), "bucket1 object(s) missing expected marker1 payload"

    s3_dest_update = json.dumps(
        {"BucketARN": bucket2_arn, "Prefix": "records/", "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60}}
    )
    _run_aws(
        ctx,
        "firehose", "update-destination",
        "--delivery-stream-name", delivery_stream_name,
        "--current-delivery-stream-version-id", version_id,
        "--destination-id", destination_id,
        "--extended-s3-destination-update", s3_dest_update,
    )
    _wait_destination_bucket(ctx, delivery_stream_name, bucket2_arn)

    marker2 = ctx.unique_name("second-")
    firehose.put_record(DeliveryStreamName=delivery_stream_name, Record={"Data": f"second-{marker2}\n".encode()})
    contents2 = _poll_s3_prefix(ctx, bucket2, "records/", timeout_s=200.0, interval_s=5.0)
    assert contents2, "record was never delivered to the updated (bucket2) destination"
    assert _bucket_contains_marker(ctx, bucket2, contents2, marker2), "bucket2 object(s) missing expected marker2 payload"

    # The record sent after the switch must not have landed in the old bucket.
    resp1_after = s3.list_objects_v2(Bucket=bucket1, Prefix="records/")
    assert not _bucket_contains_marker(ctx, bucket1, resp1_after.get("Contents", []), marker2), (
        "record sent after update-destination unexpectedly landed in the old (bucket1) destination"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s, check=check, env_extra=env_extra)
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_firehose_role(ctx, statements) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_delivery_stream_with_retry(ctx, args_list, timeout_s=150.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last_stderr = ""
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, ["aws", "--output", "json", "firehose", "create-delivery-stream", *args_list], check=False, timeout_s=30.0)
        if proc.returncode == 0:
            return
        last_stderr = proc.stderr
        time.sleep(interval_s)
    raise AssertionError(f"create-delivery-stream never succeeded (likely IAM propagation): {last_stderr[-500:]}")


def _wait_delivery_stream_active(ctx, name, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        out = _run_aws(ctx, "firehose", "describe-delivery-stream", "--delivery-stream-name", name)
        status = out["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return out["DeliveryStreamDescription"]
        time.sleep(interval_s)
    raise AssertionError(f"delivery stream {name} never became ACTIVE within {timeout_s}s")


def _wait_destination_bucket(ctx, name, expected_bucket_arn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        out = _run_aws(ctx, "firehose", "describe-delivery-stream", "--delivery-stream-name", name)
        current = out["DeliveryStreamDescription"]["Destinations"][0]["ExtendedS3DestinationDescription"]["BucketARN"]
        if current == expected_bucket_arn:
            return
        time.sleep(interval_s)
    raise AssertionError(f"delivery stream {name} destination never switched to {expected_bucket_arn}")


def _poll_s3_prefix(ctx, bucket, prefix, timeout_s=180.0, interval_s=5.0):
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        contents = resp.get("Contents", [])
        if contents:
            return contents
        time.sleep(interval_s)
    return []


def _bucket_contains_marker(ctx, bucket, contents, marker) -> bool:
    s3 = ctx.client("s3")
    for obj in contents:
        body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
        if marker.encode() in body:
            return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
