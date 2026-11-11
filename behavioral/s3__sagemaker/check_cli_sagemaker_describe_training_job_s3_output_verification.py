"""cli-sagemaker-describe-training-job-s3-output-verification."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sagemaker-describe-training-job-s3-output-verification"
GROUP = "cli-workflow"
SERVICES = ["s3", "sagemaker"]

# AWS-owned per-region ECR registry accounts that host the built-in linear-learner algorithm
# image; fixed and identical for every caller account, so pinning them is a documented constant,
# not an account-variable assumption.
_LINEAR_LEARNER_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-central-1": "664544806723",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ap-south-1": "991648021394",
    "ca-central-1": "469771592824",
    "sa-east-1": "855470959533",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws sagemaker describe-training-job` reports the OutputDataConfig.S3OutputPath that
    was set at creation, and once the job completes the referenced model artifact really
    exists at that S3 location (verified via the SDK, not just echoed-back config)."""
    require_tools("aws")

    image = _linear_learner_image(ctx)
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    data_key = "input/train.csv"
    s3.put_object(Bucket=bucket, Key=data_key, Body=_csv_training_data().encode("utf-8"))
    role_arn = _create_sagemaker_role(ctx, allow_s3=True, bucket=bucket)

    job_name = ctx.unique_name("sim2real-sm-descjob-")
    output_prefix = "training-output"
    _create_training_job_sdk_with_retry(
        ctx,
        sm,
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        InputDataConfig=[
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/{data_key}",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
                "ContentType": "text/csv",
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/{output_prefix}/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 1800},
        HyperParameters={
            "feature_dim": "2",
            "predictor_type": "binary_classifier",
            "mini_batch_size": "10",
            "epochs": "1",
            "num_models": "1",
        },
        Tags=[{"Key": "sim2real", "Value": "sm-describe-training-job-s3-output-verification"}],
    )
    ctx.on_cleanup(lambda: _stop_job_safe(ctx, job_name))

    described = _run_aws(ctx, "sagemaker", "describe-training-job", "--training-job-name", job_name)
    s3_output_path = described["OutputDataConfig"]["S3OutputPath"]
    assert s3_output_path == f"s3://{bucket}/{output_prefix}/", (
        f"CLI describe-training-job reported unexpected S3OutputPath: {s3_output_path}"
    )

    final = _wait_training_job_terminal(ctx, job_name, timeout_s=1500, interval_s=20)
    assert final["TrainingJobStatus"] == "Completed", (
        f"expected Completed, got {final['TrainingJobStatus']}: "
        f"{final.get('FailureReason', '<no reason>')}"
    )

    artifact_key = f"{output_prefix}/{job_name}/output/model.tar.gz"
    assert _object_exists(ctx, bucket, artifact_key), (
        f"expected training output artifact at s3://{bucket}/{artifact_key} referenced by "
        f"describe-training-job's OutputDataConfig"
    )


# ===== helpers =====

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
            f"  stderr: {_error_snippet(result.stderr)}"
        )
    return result


def _error_snippet(stderr: str, width: int = 400) -> str:
    """Extract the informative part of an AWS CLI error, skipping usage boilerplate."""
    lower = stderr.lower()
    idx = lower.find("error")
    if idx == -1:
        return stderr[:width]
    start = max(0, idx - 50)
    return stderr[start : start + width]


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


def _linear_learner_image(ctx) -> str:
    account = _LINEAR_LEARNER_ACCOUNTS.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no known built-in linear-learner image account mapping for region {ctx.region}"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1"


def _create_training_job_sdk_with_retry(ctx, sm, timeout_s: float = 90.0, **kwargs) -> None:
    """IAM role creation is eventually consistent: SageMaker may fail to assume a
    brand-new role for tens of seconds after create_role/put_role_policy return.
    Retry create_training_job until the role is assumable or the timeout elapses."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            sm.create_training_job(**kwargs)
            return
        except ClientError as err:
            msg = str(err)
            if "Could not assume role" in msg or "is not authorized" in msg:
                last_err = err
                time.sleep(5.0)
                continue
            raise
    raise AssertionError(
        f"create_training_job did not succeed within {timeout_s}s (role assume propagation): {last_err}"
    )


def _csv_training_data(rows: int = 60) -> str:
    lines = []
    for i in range(rows):
        label = i % 2
        f1 = 1.0 + label + (i % 5) * 0.01
        f2 = 2.0 - label + (i % 3) * 0.01
        lines.append(f"{label},{f1:.3f},{f2:.3f}")
    return "\n".join(lines) + "\n"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "sm-describe-training-job-s3-output-verification"}]},
    )
    _register_bucket_cleanup(ctx, bucket)
    return bucket


def _register_bucket_cleanup(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")

    def _cleanup():
        try:
            paginator = s3.get_paginator("list_objects_v2")
            keys = []
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    keys.append({"Key": obj["Key"]})
            for i in range(0, len(keys), 1000):
                batch = keys[i : i + 1000]
                if batch:
                    s3.delete_objects(Bucket=bucket, Delete={"Objects": batch})
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)


def _create_sagemaker_role(ctx, *, allow_s3: bool, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "sm-describe-training-job-s3-output-verification"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    if allow_s3:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        )
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    policy_name = ctx.unique_name("sim2real-sm-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _stop_job_safe(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
            raise


def _wait_training_job_terminal(ctx, job_name: str, timeout_s=1500.0, interval_s=20.0) -> dict:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sm.describe_training_job(TrainingJobName=job_name)
        if last["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"training job {job_name} did not reach a terminal state within {timeout_s}s "
        f"(last status: {last['TrainingJobStatus'] if last else '<none>'})"
    )


def _object_exists(ctx, bucket: str, key: str) -> bool:
    s3 = ctx.client("s3")
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as err:
        if err.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return False
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
