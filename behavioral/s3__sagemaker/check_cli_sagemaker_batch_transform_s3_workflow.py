"""cli-sagemaker-batch-transform-s3-workflow."""
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

CHECK = "cli-sagemaker-batch-transform-s3-workflow"
GROUP = "cli-roundtrip"
SERVICES = ["s3", "sagemaker"]

# A bring-your-own-script inference module for the AWS-owned scikit-learn framework container:
# SageMaker's inference toolkit imports this module (named by SAGEMAKER_PROGRAM, resolved under
# SAGEMAKER_SUBMIT_DIRECTORY) and calls these hooks. It deterministically upper-cases whatever
# payload it is sent. CreateModel has no entrypoint-override field — the AWS CLI itself rejects
# ContainerEntrypoint/ContainerArguments in PrimaryContainer (not part of the ContainerDefinition
# shape) — so a custom serving process can only be injected via a framework container's own
# script-loading contract, never at the API level.
_INFERENCE_SCRIPT = '''
def model_fn(model_dir):
    return {}


def input_fn(input_data, content_type):
    if isinstance(input_data, bytes):
        return input_data.decode("utf-8")
    return input_data


def predict_fn(input_data, model):
    return input_data.upper()


def output_fn(prediction, accept):
    return prediction, "text/csv"
'''

# AWS-owned "sagemaker-scikit-learn" framework container registry accounts, one per region
# (see AWS docs "Available Deep Learning Containers Images" / SageMaker framework image list).
_SKLEARN_ECR_ACCOUNT_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ca-central-1": "341280168497",
    "sa-east-1": "737474898029",
}


def _resolve_sklearn_image(ctx) -> str:
    account = _SKLEARN_ECR_ACCOUNT_BY_REGION.get(ctx.region)
    if not account:
        raise AssertionError(f"no known scikit-learn framework container account for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Upload input data to S3, launch a batch transform job via CLI against a real inference
    server, and verify the transformed output object lands in the destination S3 prefix with the
    exact (deterministic) transformation applied."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, name_suffix="transform", bucket_name=bucket)

    model_key = "artifacts/model.tar.gz"
    local_tar = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    try:
        with tarfile.open(local_tar.name, "w:gz") as tar:
            data = _INFERENCE_SCRIPT.encode("utf-8")
            info = tarfile.TarInfo(name="code/inference.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        local_tar.close()
        _run_aws(ctx, "s3", "cp", local_tar.name, f"s3://{bucket}/{model_key}")
    finally:
        os.unlink(local_tar.name)

    model_name = ctx.unique_name("sim2real-tf-model-")
    model_payload = {
        "ModelName": model_name,
        "ExecutionRoleArn": role_arn,
        "PrimaryContainer": {
            "Image": _resolve_sklearn_image(ctx),
            "ModelDataUrl": f"s3://{bucket}/{model_key}",
            "Environment": {
                "SAGEMAKER_PROGRAM": "inference.py",
                "SAGEMAKER_SUBMIT_DIRECTORY": "/opt/ml/model/code",
            },
        },
        "Tags": [{"Key": "sim2real", "Value": "cli-batch-transform"}],
    }
    _create_via_cli_with_role_retry(ctx, "sagemaker", "create-model", model_payload)
    ctx.on_cleanup(lambda: ctx.client("sagemaker").delete_model(ModelName=model_name))

    input_text = "hello,world\nfoo,bar\n"
    local_input = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    try:
        local_input.write(input_text)
        local_input.close()
        input_key = "transform-input/input.csv"
        _run_aws(ctx, "s3", "cp", local_input.name, f"s3://{bucket}/{input_key}")
    finally:
        os.unlink(local_input.name)

    job_name = ctx.unique_name("sim2real-transform-")
    output_prefix = "transform-output"
    transform_payload = {
        "TransformJobName": job_name,
        "ModelName": model_name,
        "TransformInput": {
            "DataSource": {
                "S3DataSource": {
                    "S3DataType": "S3Prefix",
                    "S3Uri": f"s3://{bucket}/{input_key}",
                }
            },
            "ContentType": "text/csv",
            "SplitType": "None",
        },
        "TransformOutput": {"S3OutputPath": f"s3://{bucket}/{output_prefix}", "AssembleWith": "None"},
        "TransformResources": {"InstanceType": "ml.m5.large", "InstanceCount": 1},
        "Tags": [{"Key": "sim2real", "Value": "cli-batch-transform"}],
    }
    _create_via_cli_with_role_retry(ctx, "sagemaker", "create-transform-job", transform_payload)

    sm = ctx.client("sagemaker")
    result = _poll_until(
        lambda: sm.describe_transform_job(TransformJobName=job_name),
        lambda r: r["TransformJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert result["TransformJobStatus"] == "Completed", (
        f"transform job did not complete: {result.get('FailureReason')}"
    )

    s3 = ctx.client("s3")
    output_obj = s3.get_object(Bucket=bucket, Key=f"{output_prefix}/input.csv.out")
    output_text = output_obj["Body"].read().decode("utf-8")
    expected = input_text.upper()
    assert output_text == expected, f"expected transformed body {expected!r}, got {output_text!r}"


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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "cli-batch-transform"}]})

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
        Tags=[{"Key": "sim2real", "Value": "cli-batch-transform"}],
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


def _create_via_cli_with_role_retry(ctx, service, operation, payload, *, timeout_s=180.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last_stderr = None
    while time.monotonic() < deadline:
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f)
            proc = _run_shell(
                ctx,
                [
                    "aws",
                    "--output",
                    "json",
                    service,
                    operation,
                    "--cli-input-json",
                    f"file://{path}",
                ],
                timeout_s=30.0,
                check=False,
            )
        finally:
            os.unlink(path)
        if proc.returncode == 0:
            return
        last_stderr = proc.stderr
        stderr_lower = proc.stderr.lower()
        role_propagation_markers = ("not authorized", "assumerole", "assume role", "ensure that the role")
        if "ValidationException" in proc.stderr and any(m in stderr_lower for m in role_propagation_markers):
            time.sleep(interval_s)
            continue
        raise AssertionError(f"{operation} failed: {proc.stderr[-500:]}")
    raise AssertionError(f"role never became usable within {timeout_s}s: {last_stderr}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
