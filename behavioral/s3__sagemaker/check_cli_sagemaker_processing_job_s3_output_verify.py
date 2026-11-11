"""cli-sagemaker-processing-job-s3-output-verify."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sagemaker-processing-job-s3-output-verify"
GROUP = "cli-roundtrip"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws sagemaker create-processing-job` output is verified present (and readable) in S3
    via a follow-up boto3 list/get-object call."""
    require_tools("aws")

    region = ctx.region
    image_uri = _processing_image_uri(region)

    bucket = _create_bucket(ctx)
    _upload_csv_via_cli(ctx, bucket, "input/data.csv")
    role_arn, _role_name = _create_sagemaker_role(ctx, allow_s3=True)

    job_name = ctx.unique_name("sim2real-sm-proc-")
    payload = {
        "ProcessingJobName": job_name,
        "RoleArn": role_arn,
        "AppSpecification": {
            "ImageUri": image_uri,
            "ContainerEntrypoint": [
                "/bin/bash",
                "-c",
                "mkdir -p /opt/ml/processing/output && "
                "cp /opt/ml/processing/input/data.csv /opt/ml/processing/output/copied.csv && "
                "echo done > /opt/ml/processing/output/result.txt",
            ],
        },
        "ProcessingInputs": [
            {
                "InputName": "input",
                "S3Input": {
                    "S3Uri": f"s3://{bucket}/input/",
                    "LocalPath": "/opt/ml/processing/input",
                    "S3DataType": "S3Prefix",
                    "S3InputMode": "File",
                    "S3DataDistributionType": "FullyReplicated",
                },
            }
        ],
        "ProcessingOutputConfig": {
            "Outputs": [
                {
                    "OutputName": "output",
                    "S3Output": {
                        "S3Uri": f"s3://{bucket}/proc-output/",
                        "LocalPath": "/opt/ml/processing/output",
                        "S3UploadMode": "EndOfJob",
                    },
                }
            ]
        },
        "ProcessingResources": {
            "ClusterConfig": {
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeSizeInGB": 1,
            }
        },
        "StoppingCondition": {"MaxRuntimeInSeconds": 1800},
    }
    _run_aws_create_with_role_retry(ctx, "sagemaker", "create-processing-job", payload)

    sm = ctx.client("sagemaker")
    job = _poll_until(
        lambda: sm.describe_processing_job(ProcessingJobName=job_name),
        lambda d: d["ProcessingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    assert job["ProcessingJobStatus"] == "Completed", (
        f"processing job did not complete: status={job['ProcessingJobStatus']} "
        f"reason={job.get('ExitMessage') or job.get('FailureReason')}"
    )

    s3 = ctx.client("s3")
    listing = s3.list_objects_v2(Bucket=bucket, Prefix="proc-output/")
    keys = {obj["Key"] for obj in listing.get("Contents", [])}
    assert "proc-output/result.txt" in keys, f"result.txt missing from {keys}"
    assert "proc-output/copied.csv" in keys, f"copied.csv missing from {keys}"

    result_obj = s3.get_object(Bucket=bucket, Key="proc-output/result.txt")
    body = result_obj["Body"].read()
    assert body == b"done\n", f"expected result.txt body b'done\\n', got {body!r}"


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with leased AWS creds + region in the
    env (via ctx.subprocess_env). Raises on non-zero exit when check=True. Returns CompletedProcess."""
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
    """Run a multi-line bash script (set -euo pipefail) with leased AWS creds configured."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(
            ctx,
            ["bash", script_path],
            timeout_s=timeout_s,
            check=check,
            env_extra=env_extra,
        )
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    """Run an AWS CLI command; return parsed JSON (dict/list) or raw stdout string."""
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", "--no-cli-pager", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


_DLC_ACCOUNT = "763104351884"
_UNSUPPORTED_REGION_PREFIXES = ("cn-", "us-gov-", "us-iso")


def _processing_image_uri(region: str) -> str:
    if region.startswith(_UNSUPPORTED_REGION_PREFIXES):
        raise AssertionError(
            f"no known Deep Learning Container registry account mapping for region {region}"
        )
    return f"{_DLC_ACCOUNT}.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup():
        while True:
            resp = s3.list_objects_v2(Bucket=name)
            contents = resp.get("Contents", [])
            if not contents:
                break
            s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            )
            if not resp.get("IsTruncated"):
                break
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _upload_csv_via_cli(ctx, bucket: str, key: str) -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write("feature1,feature2,label\n1,2,0\n3,4,1\n")
        local_path = f.name
    try:
        _run_aws(ctx, "s3", "cp", local_path, f"s3://{bucket}/{key}")
    finally:
        os.unlink(local_path)


def _create_sagemaker_role(ctx, allow_s3: bool = True):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    log_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="logs-access", PolicyDocument=json.dumps(log_policy)
    )
    if allow_s3:
        s3_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                    "Resource": "*",
                }
            ],
        }
        iam.put_role_policy(
            RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(s3_policy)
        )
    return role_arn, role_name


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    iam.delete_role(RoleName=role_name)


def _run_aws_create_with_role_retry(
    ctx, service: str, operation: str, payload: dict, timeout_s: float = 150.0, interval_s: float = 10.0
):
    """Run an `aws <service> <operation> --cli-input-json ...` call, retrying while the failure
    looks like IAM role propagation lag (the just-created role not yet assumable/passable)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        path = f.name
    try:
        deadline = time.monotonic() + timeout_s
        last_stderr = ""
        while time.monotonic() < deadline:
            proc = _run_shell(
                ctx,
                [
                    "aws",
                    "--output",
                    "json",
                    "--no-cli-pager",
                    service,
                    operation,
                    "--cli-input-json",
                    f"file://{path}",
                ],
                timeout_s=30.0,
                check=False,
            )
            if proc.returncode == 0:
                return json.loads(proc.stdout) if proc.stdout.strip() else {}
            last_stderr = proc.stderr
            if (
                "is not authorized" in proc.stderr
                or "AccessDenied" in proc.stderr
                or "ValidationException" in proc.stderr
            ):
                time.sleep(interval_s)
                continue
            raise AssertionError(f"{service} {operation} failed: {proc.stderr[-500:]}")
        raise AssertionError(
            f"{service} {operation} did not succeed after role-propagation retries: "
            f"{last_stderr[-500:]}"
        )
    finally:
        os.unlink(path)


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
