"""cli-kinesis-put-record-firehose-delivers-s3-workflow."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-kinesis-put-record-firehose-delivers-s3-workflow"
GROUP = "cli-roundtrip"
SERVICES = ["firehose", "kinesis", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CLI creates a Kinesis stream, wires it as a Firehose KinesisStreamAsSource, puts a
    record via the CLI, and the record's payload lands as an S3 object (verified via SDK)."""
    require_tools("aws")

    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    stream_name = ctx.unique_name("sim2real-fh-src-")
    _run_aws(ctx, "kinesis", "create-stream", "--stream-name", stream_name, "--shard-count", "1")
    ctx.on_cleanup(lambda: _cli_teardown(ctx, ["aws", "kinesis", "delete-stream", "--stream-name", stream_name]))
    _run_aws(ctx, "kinesis", "add-tags-to-stream", "--stream-name", stream_name, "--tags", f"sim2real={CHECK}")
    stream_desc = _wait_stream_active(ctx, stream_name)
    stream_arn = stream_desc["StreamARN"]

    role_arn = _create_firehose_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["kinesis:DescribeStream", "kinesis:GetShardIterator", "kinesis:GetRecords", "kinesis:ListShards"],
                "Resource": stream_arn,
            },
            {
                "Effect": "Allow",
                "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
        ],
    )

    delivery_stream_name = ctx.unique_name("sim2real-fh-ds-")
    kinesis_source_config = json.dumps({"KinesisStreamARN": stream_arn, "RoleARN": role_arn})
    s3_dest_config = json.dumps(
        {
            "RoleARN": role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "Prefix": "records/",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        }
    )
    _create_delivery_stream_with_retry(
        ctx,
        [
            "--delivery-stream-name", delivery_stream_name,
            "--delivery-stream-type", "KinesisStreamAsSource",
            "--kinesis-stream-source-configuration", kinesis_source_config,
            "--extended-s3-destination-configuration", s3_dest_config,
            "--tags", f"Key=sim2real,Value={CHECK}",
        ],
    )
    ctx.on_cleanup(lambda: _delete_delivery_stream(ctx, delivery_stream_name))
    _wait_delivery_stream_active(ctx, delivery_stream_name)

    marker = ctx.unique_name("payload-")

    def _put_record(text: str) -> None:
        # The `--data` blob argument for `kinesis put-record` takes base64 text under this
        # CLI's default `cli_binary_format=base64` (AWS CLI v2) — it is not auto-encoded from
        # raw text, so the raw payload is base64-encoded here before it is passed.
        encoded = base64.b64encode(text.encode()).decode()
        _run_aws(ctx, "kinesis", "put-record", "--stream-name", stream_name, "--partition-key", "pk1", "--data", encoded)

    _put_record(f"hello-{marker}-0\n")

    # A Kinesis-sourced stream can start reading minutes after it reports ACTIVE, and the 60 s buffer must
    # also elapse. Re-send the marker every 30 s so delivery does not hinge on the first send.
    found = False
    attempt = 0
    left = ctx.time_left()
    deadline = time.monotonic() + (300.0 if left is None else max(1.0, min(300.0, left - 5.0)))
    next_send = time.monotonic() + 30.0
    while time.monotonic() < deadline and not found:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix="records/")
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            if marker.encode() in body:
                found = True
                break
        if found:
            break
        if time.monotonic() >= next_send:
            attempt += 1
            _put_record(f"hello-{marker}-{attempt}\n")
            next_send += 30.0
        time.sleep(2.0)

    assert found, f"delivered S3 object(s) never contained the expected marker {marker!r} within the poll budget"


# ===== helpers =====


def _cli_teardown(ctx, command):
    """Run a CLI delete in teardown: an already-gone resource is fine, any other failure raises."""
    proc = _run_shell(ctx, command, check=False)
    if proc.returncode != 0 and "ResourceNotFoundException" not in proc.stderr:
        raise AssertionError(f"teardown {command} failed (rc={proc.returncode}): {proc.stderr[-500:]}")


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
    # us-east-1 is the one region where CreateBucket rejects an explicit
    # LocationConstraint (it is the API's default region), so the literal here
    # is a required transport quirk, not a region pin on the bucket itself.
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


def _wait_stream_active(ctx, name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        out = _run_aws(ctx, "kinesis", "describe-stream", "--stream-name", name)
        status = out["StreamDescription"]["StreamStatus"]
        if status == "ACTIVE":
            return out["StreamDescription"]
        time.sleep(interval_s)
    raise AssertionError(f"kinesis stream {name} never became ACTIVE within {timeout_s}s")


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
