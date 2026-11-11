"""cli-sagemaker-create-model-s3-artifact-workflow."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sagemaker-create-model-s3-artifact-workflow"
GROUP = "sdk-cli-interop"
SERVICES = ["s3", "sagemaker"]


def _model_image(ctx):
    """CreateModel validates that the execution role can pull the image, so this must be a
    real, accessible container — use the AWS-owned SageMaker PyTorch inference Deep Learning
    Container (account 763104351884 is stable across commercial regions), avoiding any
    dependency on the optional `sagemaker` SDK or a container push of our own."""
    return f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-inference:2.1.0-cpu-py310-ubuntu20.04-sagemaker"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Upload a model artifact to S3, create a SageMaker model via CLI referencing it, then
    verify via the SDK that the model's container config (image, ModelDataUrl, role) persisted
    exactly as requested."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, name_suffix="model", bucket_name=bucket)
    model_image = _model_image(ctx)

    local_tar = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    try:
        with tarfile.open(local_tar.name, "w:gz") as tar:
            info = tarfile.TarInfo(name="placeholder.txt")
            data = b"placeholder-model-artifact\n"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        local_tar.close()
        model_key = "artifacts/model.tar.gz"
        _run_aws(ctx, "s3", "cp", local_tar.name, f"s3://{bucket}/{model_key}")
    finally:
        os.unlink(local_tar.name)

    model_name = ctx.unique_name("sim2real-model-")
    model_data_url = f"s3://{bucket}/{model_key}"
    payload = {
        "ModelName": model_name,
        "ExecutionRoleArn": role_arn,
        "PrimaryContainer": {
            "Image": model_image,
            "ModelDataUrl": model_data_url,
        },
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    _run_aws_cli_input_json_with_retry(ctx, "sagemaker", "create-model", payload=payload)
    ctx.on_cleanup(lambda: ctx.client("sagemaker").delete_model(ModelName=model_name))

    sm = ctx.client("sagemaker")
    described = sm.describe_model(ModelName=model_name)
    assert described["PrimaryContainer"]["Image"] == model_image, (
        f"DescribeModel PrimaryContainer.Image {described['PrimaryContainer']['Image']!r} "
        f"does not match the image passed to the CLI create-model call {model_image!r}"
    )
    assert described["PrimaryContainer"]["ModelDataUrl"] == model_data_url, (
        f"DescribeModel PrimaryContainer.ModelDataUrl {described['PrimaryContainer']['ModelDataUrl']!r} "
        f"does not match the S3 URI passed to the CLI create-model call {model_data_url!r}"
    )
    assert described["ExecutionRoleArn"] == role_arn, (
        f"DescribeModel ExecutionRoleArn {described['ExecutionRoleArn']!r} does not match "
        f"the role passed to the CLI create-model call {role_arn!r}"
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


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _run_aws_cli_input_json_with_retry(
    ctx, *args: str, payload: dict, timeout_s=60.0, retry_deadline_s=90.0, interval_s=10.0
):
    """CreateModel validates the ExecutionRoleArn's S3 access synchronously — IAM role/policy
    propagation lags create_role+put_role_policy, so an immediate call can see a stale trust/
    permission view. Retry on that specific AccessDenied/role-not-found shape until it propagates,
    judging each attempt by its exit code and stderr; any other failure raises at once."""
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        command = ["aws", "--output", "json", *args, "--cli-input-json", f"file://{path}"]
        deadline = time.monotonic() + retry_deadline_s
        while True:
            proc = _run_shell(ctx, command, timeout_s=timeout_s, check=False)
            if proc.returncode == 0:
                break
            stderr = proc.stderr
            transient = (
                "AccessDenied" in stderr
                or "is not authorized" in stderr
                or "Please ensure that the role" in stderr
                or "trust relationship" in stderr
            )
            if not transient or time.monotonic() >= deadline:
                raise AssertionError(
                    f"Command failed (rc={proc.returncode}):\n  cmd: {command}\n"
                    f"  stderr: {stderr[-500:]}"
                )
            time.sleep(interval_s)
    finally:
        os.unlink(path)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-s3-").lower().replace("_", "-")
    # us-east-1 is the one region where S3 CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
