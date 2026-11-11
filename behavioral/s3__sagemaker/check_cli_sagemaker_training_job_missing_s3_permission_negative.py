"""cli-sagemaker-training-job-missing-s3-permission-negative."""
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

CHECK = "cli-sagemaker-training-job-missing-s3-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

# A public.ecr.aws / Docker Hub image makes SageMaker demand a VPC TrainingImageConfig
# ("training image from a private Docker registry"); the account-scoped Deep Learning
# Container ECR repos are what SageMaker accepts without that extra VPC wiring.
_DLC_ACCOUNT = "763104351884"
_UNSUPPORTED_REGION_PREFIXES = ("cn-", "us-gov-", "us-iso")


def _training_image_uri(region: str) -> str:
    if region.startswith(_UNSUPPORTED_REGION_PREFIXES):
        raise AssertionError(f"no known Deep Learning Container registry account mapping for region {region}")
    return f"{_DLC_ACCOUNT}.dkr.ecr.{region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310"


# SageMaker caps a single ContainerArguments member at 256 chars, so this has to be a
# single compact statement rather than the natural multi-line script.
_TRAIN_SCRIPT = (
    'import glob;t=sum(sum(1 for _ in open(f)) for f in '
    'glob.glob("/opt/ml/input/data/train/*"));'
    'open("/opt/ml/model/artifact.txt","w").write("total_lines:%d\\n"%t);'
    'print("training-complete total_lines=%d"%t)'
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateTrainingJob with a role lacking any S3 access is rejected at creation with a
    ValidationException citing s3:ListBucket, so no job ever exists, while an identical job with
    an S3-capable role (positive control) completes and produces a model artifact."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    num_rows = 20
    local_csv = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    try:
        for i in range(num_rows):
            local_csv.write(f"{i},{i * 2}\n")
        local_csv.close()
        _run_aws(ctx, "s3", "cp", local_csv.name, f"s3://{bucket}/train/data.csv")
    finally:
        os.unlink(local_csv.name)

    image_uri = _training_image_uri(ctx.region)
    role_good = _create_sagemaker_role(ctx, name_suffix="good", allow_s3=True, bucket_name=bucket)
    role_bad = _create_sagemaker_role(ctx, name_suffix="bad", allow_s3=False, bucket_name=bucket)

    job_good = ctx.unique_name("sim2real-train-good-")
    job_bad = ctx.unique_name("sim2real-train-bad-")

    def _payload(job_name, role_arn, output_prefix):
        return {
            "TrainingJobName": job_name,
            "RoleArn": role_arn,
            "AlgorithmSpecification": {
                "TrainingImage": image_uri,
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
            "Tags": [{"Key": "sim2real", "Value": "training-job-missing-s3-permission-negative"}],
        }

    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")

    # Negative: CreateTrainingJob itself rejects a role with no S3 access at all, synchronously
    # (ValidationException, s3:ListBucket AccessDenied), never by minting a job that later fails.
    rejection_stderr = _create_training_job_expect_rejection(ctx, _payload(job_bad, role_bad, "output-bad"))
    expected_message = _no_s3_objects_message(
        ctx, f"s3://{bucket}/train/data.csv", bucket, role_bad, list_denied=True
    )
    assert rejection_stderr.strip() == (
        "aws: [ERROR]: An error occurred (ValidationException) when calling the CreateTrainingJob "
        "operation: "
        f"{expected_message}"
    ), rejection_stderr

    try:
        sm.describe_training_job(TrainingJobName=job_bad)
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ValidationException", e.response["Error"]
        assert e.response["Error"]["Message"] == "Requested resource not found.", e.response["Error"]
    else:
        raise AssertionError("describe_training_job found a job whose creation should have been rejected")

    listing = s3.list_objects_v2(Bucket=bucket, Prefix="output-bad")
    assert "Contents" not in listing, "no model artifact should exist -- the training job was never created"

    # Positive control: identical setup, role WITH S3 access -- proves the rejection above is
    # specifically the missing permission, not something else about the fixture.
    _create_training_job_via_cli_with_role_retry(ctx, _payload(job_good, role_good, "output-good"))
    ctx.on_cleanup(lambda: _stop_training_job_ignore_errors(sm, job_good))

    result_good = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_good),
        lambda r: r["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert result_good["TrainingJobStatus"] == "Completed", (
        f"positive control did not complete: {result_good.get('FailureReason')}"
    )
    model_s3_uri = result_good["ModelArtifacts"]["S3ModelArtifacts"]
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
        # us-east-1 rejects CreateBucketConfiguration/LocationConstraint outright.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "training-job-missing-s3-permission-negative"}]},
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _create_training_job_expect_rejection(ctx, payload, *, timeout_s=180.0, interval_s=10.0):
    """Submit create-training-job for a role with no S3 access, retrying only while the
    rejection looks like IAM role-assumption propagation lag ("Could not assume role ...") rather
    than the S3 permission denial under test. Returns the terminal stderr. Raises if the call
    unexpectedly succeeds, or if the role never becomes assumable within the deadline."""
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            proc = _run_shell(
                ctx,
                ["aws", "--output", "json", "sagemaker", "create-training-job", "--cli-input-json", f"file://{path}"],
                timeout_s=30.0,
                check=False,
            )
            if proc.returncode == 0:
                raise AssertionError(
                    f"create-training-job unexpectedly succeeded for a role with no S3 access at all: {proc.stdout}"
                )
            if "assume role" in proc.stderr.lower() or "assume the role" in proc.stderr.lower():
                time.sleep(interval_s)
                continue
            return proc.stderr
        raise AssertionError(f"role never became assumable within {timeout_s}s")
    finally:
        os.unlink(path)


def _stop_training_job_ignore_errors(sm, job_name: str) -> None:
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


def _no_s3_objects_message(ctx, s3_uri: str, bucket: str, role_arn: str, *, list_denied: bool) -> str:
    """SageMaker's exact refusal when an input channel's S3 prefix lists no objects for the role."""
    message = (
        f'No S3 objects found under S3 URL "{s3_uri}" given in input data source. Please ensure '
        f"that the bucket exists in the selected region ({ctx.region}), that objects exist under "
        f'that S3 prefix, and that the role "{role_arn}" has "s3:ListBucket" permissions on '
        f'bucket "{bucket}".'
    )
    if list_denied:
        role_name = role_arn.rsplit("/", 1)[-1]
        message += (
            f" Error message from S3: User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/"
            f'SageMaker is not authorized to perform: s3:ListBucket on resource: "arn:aws:s3:::'
            f'{bucket}" because no identity-based policy allows the s3:ListBucket action'
        )
    return message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
