"""cli-s3-upload-then-sagemaker-processing-job-workflow."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-s3-upload-then-sagemaker-processing-job-workflow"
GROUP = "cli-script"
SERVICES = ["s3", "sagemaker"]

# CreateProcessingJob rejects a public ECR Gallery image ("Please provide a valid Amazon
# Elastic Container Registry path") -- it must be an ECR-hosted image, so this points at the
# AWS Deep Learning Containers registry (same account other s3__sagemaker CLI checks use).
_DLC_ACCOUNT = "763104351884"


def _proc_image_uri(region: str) -> str:
    return f"{_DLC_ACCOUNT}.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"


# Upper-cases every file under /opt/ml/processing/input into the matching filename under
# /opt/ml/processing/output -- a deterministic transform we can assert against after the job.
# Kept as a single `tr` pipeline (not a Python script passed inline) because
# AppSpecification.ContainerArguments caps each member at 256 chars on real AWS.
_PROC_SCRIPT = (
    'mkdir -p /opt/ml/processing/output && '
    'for f in /opt/ml/processing/input/*; do '
    'tr "[:lower:]" "[:upper:]" < "$f" > "/opt/ml/processing/output/$(basename "$f")"; '
    'done'
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Script an `aws s3 sync` of local files into S3 followed by a `create-processing-job` CLI
    call in the same shell script, then verify the processed (upper-cased) output objects
    actually landed in the destination S3 prefix via the SDK."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, name_suffix="proc", bucket_name=bucket)

    input_prefix = "proc-input"
    output_prefix = "proc-output"
    files = {"a.txt": "alpha content\n", "b.txt": "beta content\n"}

    local_dir = tempfile.mkdtemp()
    try:
        for name, content in files.items():
            with open(os.path.join(local_dir, name), "w") as f:
                f.write(content)

        job_name = ctx.unique_name("sim2real-proc-")
        payload = {
            "ProcessingJobName": job_name,
            "RoleArn": role_arn,
            "AppSpecification": {
                "ImageUri": _proc_image_uri(ctx.region),
                "ContainerEntrypoint": ["/bin/bash", "-c"],
                "ContainerArguments": [_PROC_SCRIPT],
            },
            "ProcessingInputs": [
                {
                    "InputName": "input",
                    "S3Input": {
                        "S3Uri": f"s3://{bucket}/{input_prefix}/",
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
                            "S3Uri": f"s3://{bucket}/{output_prefix}/",
                            "LocalPath": "/opt/ml/processing/output",
                            "S3UploadMode": "EndOfJob",
                        },
                    }
                ]
            },
            "ProcessingResources": {
                "ClusterConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5}
            },
            "StoppingCondition": {"MaxRuntimeInSeconds": 900},
        }
        payload_path = os.path.join(local_dir, "processing_job.json")
        with open(payload_path, "w") as f:
            json.dump(payload, f)

        script = (
            f'aws s3 sync "{local_dir}" "s3://{bucket}/{input_prefix}/" --exclude "processing_job.json"\n'
            f'aws sagemaker create-processing-job --cli-input-json "file://{payload_path}"\n'
        )
        _create_processing_job_with_role_retry(ctx, script, role_arn, job_name)
    finally:
        shutil.rmtree(local_dir, ignore_errors=True)

    sm = ctx.client("sagemaker")
    result = _poll_until(
        lambda: sm.describe_processing_job(ProcessingJobName=job_name),
        lambda r: r["ProcessingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert result["ProcessingJobStatus"] == "Completed", (
        f"processing job did not complete: {result.get('FailureReason')}"
    )

    s3 = ctx.client("s3")
    for name, content in files.items():
        obj = s3.get_object(Bucket=bucket, Key=f"{output_prefix}/{name}")
        body = obj["Body"].read().decode("utf-8")
        assert body == content.upper(), (
            f"{output_prefix}/{name}: expected {content.upper()!r}, got {body!r}"
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
        return _run_shell(
            ctx,
            ["bash", script_path],
            timeout_s=timeout_s,
            check=check,
            env_extra=env_extra,
        )
    finally:
        os.unlink(script_path)


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-s3-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_sagemaker_role(ctx, *, name_suffix, bucket_name):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-sm-role-{name_suffix}-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "logs:DescribeLogStreams",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_processing_job_with_role_retry(ctx, script, role_arn, job_name, *, timeout_s=180.0, interval_s=10.0):
    """A freshly created IAM role can take tens of seconds to propagate; retry the whole
    sync+create-processing-job script until SageMaker accepts the role."""
    deadline = time.monotonic() + timeout_s
    last_stderr = None
    while time.monotonic() < deadline:
        proc = _run_script(ctx, script, timeout_s=60.0, check=False)
        if proc.returncode == 0:
            return
        last_stderr = proc.stderr
        if "ValidationException" in proc.stderr and (
            "not authorized" in proc.stderr or "assume role" in proc.stderr.lower()
        ):
            time.sleep(interval_s)
            continue
        raise AssertionError(f"create-processing-job script failed: {proc.stderr[-500:]}")
    raise AssertionError(f"role never became usable within {timeout_s}s: {last_stderr}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
