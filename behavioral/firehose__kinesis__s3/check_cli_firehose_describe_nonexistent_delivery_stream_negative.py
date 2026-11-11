"""cli-firehose-describe-nonexistent-delivery-stream-negative."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-firehose-describe-nonexistent-delivery-stream-negative"
GROUP = "overly-permissive"
SERVICES = ["firehose", "kinesis", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CLI describe-delivery-stream and PutRecord on a never-created name both fail with
    ResourceNotFoundException and their exact messages and nothing lands in S3, while a real
    stream describes ACTIVE with its bucket ARN."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    )

    real_name = ctx.unique_name("sim2real-fh-real-")
    bucket_arn = f"arn:aws:s3:::{bucket}"
    s3_dest_config = json.dumps(
        {"RoleARN": role_arn, "BucketARN": bucket_arn, "Prefix": "records/", "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60}}
    )
    _create_delivery_stream_with_retry(
        ctx,
        [
            "--delivery-stream-name", real_name,
            "--delivery-stream-type", "DirectPut",
            "--extended-s3-destination-configuration", s3_dest_config,
            "--tags", f"Key=sim2real,Value={CHECK}",
        ],
    )
    ctx.on_cleanup(lambda: _delete_delivery_stream(ctx, real_name))
    real_desc = _wait_delivery_stream_active(ctx, real_name)

    # Positive control: the real delivery stream describes successfully with the expected destination.
    status = real_desc["DeliveryStreamStatus"]
    assert status == "ACTIVE", f"expected real delivery stream ACTIVE, got {status!r}"
    described_bucket_arn = real_desc["Destinations"][0]["ExtendedS3DestinationDescription"]["BucketARN"]
    assert described_bucket_arn == bucket_arn, f"expected destination BucketARN {bucket_arn!r}, got {described_bucket_arn!r}"

    # Negative: a delivery stream name that was never created.
    missing_name = ctx.unique_name("sim2real-fh-missing-")
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", "firehose", "describe-delivery-stream", "--delivery-stream-name", missing_name],
        check=False,
    )
    assert proc.returncode != 0, "describe-delivery-stream unexpectedly succeeded for a delivery stream that was never created"
    code, message = _error_from_cli_stderr(proc.stderr)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} (stderr={proc.stderr[-300:]!r})"
    want_describe = f"Firehose under account {ctx.account} not found."
    assert message == want_describe, f"expected describe message {want_describe!r}, got {message!r}"

    # No S3 delivery is possible for a delivery stream that does not exist: PutRecord is
    # equally rejected, confirming the effect (delivery) is entirely absent, not merely the describe.
    firehose = ctx.client("firehose")
    put_code, put_message = _error(lambda: firehose.put_record(DeliveryStreamName=missing_name, Record={"Data": b"never-delivered\n"}))
    assert put_code == "ResourceNotFoundException", f"expected ResourceNotFoundException on PutRecord, got {put_code!r}"
    want_put = f"Firehose not found under account {ctx.account}."
    assert put_message == want_put, f"expected PutRecord message {want_put!r}, got {put_message!r}"

    # Terminal read at the consumer, not just the producer's error code: nothing from the
    # rejected PutRecord ever lands in the S3 destination.
    listing = ctx.client("s3").list_objects_v2(Bucket=bucket, Prefix="records/")
    assert "Contents" not in listing, f"expected no objects delivered to s3 destination, found {listing.get('Contents')!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _error_from_cli_stderr(stderr: str):
    """(code, message) from the CLI's `An error occurred (<code>) when calling the <op> operation:
    <message>` line; (None, None) when stderr carries no such line."""
    m = re.search(r"An error occurred \(([A-Za-z0-9]+)\) when calling the [A-Za-z0-9]+ operation: (.*)", stderr)
    return (m.group(1), m.group(2).strip()) if m else (None, None)


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


# Inside the suite's 900 s cleanup budget; the other teardowns of the check return at once.
_STREAM_TEARDOWN_S = 600.0


def _delete_delivery_stream(ctx, name: str) -> None:
    """DeleteDeliveryStream, then poll every 2 s until DescribeDeliveryStream answers
    ResourceNotFoundException. A stream still CREATING refuses the delete with ResourceInUseException,
    which is retried; any other failure, or the deadline passing, raises."""
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    deadline = time.monotonic() + _STREAM_TEARDOWN_S
    deleted = False
    while True:
        try:
            if not deleted:
                firehose.delete_delivery_stream(DeliveryStreamName=name)
                deleted = True
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present at the teardown deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
