"""cli-sagemaker-create-training-job-s3-input-workflow."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sagemaker-create-training-job-s3-input-workflow"
GROUP = "sdk-cli-interop"
SERVICES = ["s3", "sagemaker"]

# A SageMaker Deep Learning Container: an AWS-owned per-region ECR repo, used as a
# bring-your-own container purely for its `python3` runtime (ContainerEntrypoint below
# replaces its actual training logic). Real AWS rejects (ValidationException) any
# TrainingImage CreateTrainingJob treats as a "private Docker registry" -- which includes
# the public ECR Gallery -- unless the job also runs inside a VPC that can reach it
# (TrainingImageConfig.TrainingRepositoryAccessMode=Vpc + VpcConfig); an AWS-owned DLC
# registry needs neither, so it is the cheaper choice here.
_DLC_ACCOUNT = "763104351884"
_UNSUPPORTED_REGION_PREFIXES = ("cn-", "us-gov-", "us-iso")


def _training_image_uri(region: str) -> str:
    if region.startswith(_UNSUPPORTED_REGION_PREFIXES):
        raise AssertionError(f"no known Deep Learning Container registry account mapping for region {region}")
    return f"{_DLC_ACCOUNT}.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"

# Shipped as an object in its own "code" input channel rather than a `python3 -c <script>`
# ContainerArgument: CreateTrainingJob rejects any AlgorithmSpecification.ContainerArguments
# member longer than 256 characters, and this script is well over that. SageMaker downloads
# every channel -- "code" included -- to /opt/ml/input/data/<channel>/ before the container
# starts, so the entrypoint can just execute the file by path.
#
# Reads every file staged under the "train" input channel and writes a small model artifact
# recording how many lines it saw -- this lets the check assert the job genuinely read the S3
# input data end to end, not merely that CreateTrainingJob returned 200.
_TRAIN_SCRIPT = r"""
import glob, os
out_dir = "/opt/ml/model"
os.makedirs(out_dir, exist_ok=True)
files = sorted(glob.glob("/opt/ml/input/data/train/*"))
total = 0
for f in files:
    with open(f) as fh:
        total += sum(1 for _ in fh)
with open(os.path.join(out_dir, "artifact.txt"), "w") as out:
    out.write("files:" + ",".join(os.path.basename(f) for f in files) + "\n")
    out.write("total_lines:" + str(total) + "\n")
print("training-complete total_lines=" + str(total))
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Stage S3 training data via `aws s3 cp`, launch a training job via CLI, and verify the
    completed job actually read that data (line count in the model artifact matches)."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, name_suffix="train", allow_s3=True, bucket_name=bucket)

    num_rows = 40
    local_csv = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    try:
        for i in range(num_rows):
            local_csv.write(f"{i},{i * 2},{i * 3}\n")
        local_csv.close()
        _run_aws(ctx, "s3", "cp", local_csv.name, f"s3://{bucket}/train/data.csv")
    finally:
        os.unlink(local_csv.name)

    local_script = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    try:
        local_script.write(_TRAIN_SCRIPT)
        local_script.close()
        _run_aws(ctx, "s3", "cp", local_script.name, f"s3://{bucket}/code/train.py")
    finally:
        os.unlink(local_script.name)

    job_name = ctx.unique_name("sim2real-train-")
    payload = {
        "TrainingJobName": job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingImage": _training_image_uri(ctx.region),
            "TrainingInputMode": "File",
            "ContainerEntrypoint": ["python3", "/opt/ml/input/data/code/train.py"],
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
            },
            {
                "ChannelName": "code",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/code/train.py",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            },
        ],
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        "StoppingCondition": {"MaxRuntimeInSeconds": 900},
        "Tags": [{"Key": "sim2real", "Value": "training-job-s3-input-workflow"}],
    }
    _create_training_job_via_cli_with_role_retry(ctx, payload)
    ctx.on_cleanup(lambda: _stop_job_safe(ctx, job_name))

    sm = ctx.client("sagemaker")
    result = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_name),
        lambda r: r["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert result["TrainingJobStatus"] == "Completed", (
        f"training job did not complete: {result.get('FailureReason')}"
    )

    model_s3_uri = result["ModelArtifacts"]["S3ModelArtifacts"]
    artifact_text = _read_tar_member_from_s3(ctx, model_s3_uri, "artifact.txt")
    assert f"total_lines:{num_rows}" in artifact_text, artifact_text


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


def _run_aws_cli_input_json(ctx, *args: str, payload: dict, timeout_s=60.0):
    """Like _run_aws but ships a nested request body via --cli-input-json file://<tmp> so
    complex/nested JSON (container entrypoints, S3 data sources) never needs shell escaping."""
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        proc = _run_shell(
            ctx,
            ["aws", "--output", "json", *args, "--cli-input-json", f"file://{path}"],
            timeout_s=timeout_s,
        )
    finally:
        os.unlink(path)
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
    # us-east-1 is the one region where S3 rejects an explicit LocationConstraint on
    # CreateBucket; this is an S3 API quirk, not a genuine region pin.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "training-job-s3-input-workflow"}]}
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
        Tags=[{"Key": "sim2real", "Value": "training-job-s3-input-workflow"}],
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
    """A freshly created IAM role can take tens of seconds to propagate; retry CreateTrainingJob
    until SageMaker accepts the role rather than failing on a transient AssumeRole rejection."""
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


def _stop_job_safe(ctx, job_name):
    sm = ctx.client("sagemaker")
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
            raise


def _read_tar_member_from_s3(ctx, s3_uri, member_name):
    assert s3_uri.startswith("s3://"), f"expected an s3:// URI, got {s3_uri!r}"
    bucket, _, key = s3_uri[len("s3://"):].partition("/")
    s3 = ctx.client("s3")
    data = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        member = tar.extractfile(member_name)
        return member.read().decode("utf-8")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
