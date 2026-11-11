"""cli-sagemaker-describe-training-job-verify-s3-output."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sagemaker-describe-training-job-verify-s3-output"
GROUP = "sdk-cli-interop"
SERVICES = ["s3", "sagemaker"]

# SageMaker training instances have no internet route by default, so a training image must live
# in a same-region ECR repo (customer or AWS-owned) rather than a registry reachable only over the
# internet (Docker Hub, ECR Public): pulling from the latter rejects with ValidationException
# ("TrainingImageConfig with TrainingRepositoryAccessMode set to VPC must be provided") unless the
# job is also given a VPC with NAT/internet egress. The Deep Learning Containers account below is
# a same-region ECR repo, so no VPC is needed; ContainerEntrypoint/ContainerArguments override its
# normal training toolkit entrypoint with an arbitrary inline script.
_DLC_ACCOUNT = "763104351884"


def _train_image_uri(region: str) -> str:
    return f"{_DLC_ACCOUNT}.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"

# Passed verbatim as a single AlgorithmSpecification.ContainerArguments element: SageMaker caps
# each element at 256 chars AND validates it against a single-line pattern, so this must be both
# compact and newline-free (a multi-line string fails "failed to satisfy constraint" on real AWS).
_TRAIN_SCRIPT = (
    'import os,glob;'
    'os.makedirs("/opt/ml/model",exist_ok=True);'
    '[open(f).close() for f in glob.glob("/opt/ml/input/data/train/*")];'
    'open("/opt/ml/model/artifact.txt","w").write("done");'
    'print("training-complete")'
)
_has_newline = "\n" in _TRAIN_SCRIPT
assert not _has_newline and len(_TRAIN_SCRIPT) <= 256, (
    f"_TRAIN_SCRIPT must be a single line <= 256 chars (SageMaker ContainerArguments limit); "
    f"got {len(_TRAIN_SCRIPT)} chars, newline={_has_newline}"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Poll `aws sagemaker describe-training-job` (CLI) to completion, then verify the reported
    ModelArtifacts.S3ModelArtifacts path is a real, non-empty object via the S3 SDK."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, name_suffix="describe", allow_s3=True, bucket_name=bucket)

    local_csv = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    try:
        for i in range(10):
            local_csv.write(f"{i},{i * 2}\n")
        local_csv.close()
        _run_aws(ctx, "s3", "cp", local_csv.name, f"s3://{bucket}/train/data.csv")
    finally:
        os.unlink(local_csv.name)

    job_name = ctx.unique_name("sim2real-train-")
    output_prefix = "training-output"
    payload = {
        "TrainingJobName": job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingImage": _train_image_uri(ctx.region),
            "TrainingInputMode": "File",
            "ContainerEntrypoint": ["python3"],
            "ContainerArguments": ["-c", _TRAIN_SCRIPT],
        },
        "InputDataConfig": [
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/train/data.csv",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/{output_prefix}"},
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        "StoppingCondition": {"MaxRuntimeInSeconds": 900},
    }
    _create_training_job_via_cli_with_role_retry(ctx, payload)

    described = _poll_until(
        lambda: _run_aws(ctx, "sagemaker", "describe-training-job", "--training-job-name", job_name),
        lambda r: r.get("TrainingJobStatus") in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert described["TrainingJobStatus"] == "Completed", (
        f"training job did not complete: {described.get('FailureReason')}"
    )

    model_s3_uri = described["ModelArtifacts"]["S3ModelArtifacts"]
    expected_prefix = f"s3://{bucket}/{output_prefix}/{job_name}/"
    assert model_s3_uri.startswith(expected_prefix), (
        f"expected ModelArtifacts.S3ModelArtifacts to start with {expected_prefix!r}, "
        f"got {model_s3_uri!r}"
    )
    assert model_s3_uri.endswith("model.tar.gz"), (
        f"expected ModelArtifacts.S3ModelArtifacts to end with 'model.tar.gz', got {model_s3_uri!r}"
    )

    s3 = ctx.client("s3")
    _, _, key = model_s3_uri[len("s3://"):].partition("/")
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] > 0, (
        f"model artifact at s3://{bucket}/{key} reported by describe-training-job is empty "
        f"(ContentLength={head['ContentLength']})"
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
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
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


def _create_sagemaker_role(ctx, *, name_suffix, allow_s3, bucket_name=None):
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

    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    if allow_s3 and bucket_name:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        )
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_training_job_via_cli_with_role_retry(ctx, payload, *, timeout_s=180.0, interval_s=10.0):
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
                    "sagemaker",
                    "create-training-job",
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
        if "ValidationException" in proc.stderr and (
            "not authorized" in proc.stderr or "assume role" in proc.stderr.lower()
        ):
            time.sleep(interval_s)
            continue
        raise AssertionError(f"create-training-job failed: {proc.stderr[-500:]}")
    raise AssertionError(f"role never became usable within {timeout_s}s: {last_stderr}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
