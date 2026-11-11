"""cli-sagemaker-invalid-s3-input-uri-negative."""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sagemaker-invalid-s3-input-uri-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

# CreateTrainingJob rejects a training image that is not in an ECR registry it recognizes
# (a Docker Hub / public.ecr.aws reference fails synchronously with "TrainingImageConfig with
# TrainingRepositoryAccessMode set to VPC must be provided when using a training image from a
# private Docker registry" -- unrelated to the S3Uri under test). Reuse SageMaker's own built-in
# XGBoost ECR image per-region instead; its ContainerEntrypoint is overridable with a plain
# python3 script because the container image itself is a standard Python environment.
_XGBOOST_REGISTRY_ACCOUNTS = {
    "af-south-1": "510948584623", "ap-east-1": "651117190479",
    "ap-northeast-1": "354813040037", "ap-northeast-2": "366743142698",
    "ap-northeast-3": "867004704886", "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041", "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497", "eu-central-1": "492215442770",
    "eu-north-1": "662702820516", "eu-south-1": "978288397137",
    "eu-west-1": "141502667606", "eu-west-2": "764974769150",
    "eu-west-3": "659782779980", "me-south-1": "801668240914",
    "sa-east-1": "737474898029", "us-east-1": "683313688378",
    "us-east-2": "257758044811", "us-west-1": "746614075791",
    "us-west-2": "246618743249",
}


def _train_image_uri(ctx) -> str:
    try:
        from sagemaker import image_uris
        return image_uris.retrieve(framework="xgboost", region=ctx.region, version="1.5-1")
    except Exception:
        pass
    account = _XGBOOST_REGISTRY_ACCOUNTS.get(ctx.region)
    if not account:
        raise AssertionError(f"no known built-in XGBoost ECR registry account for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.5-1"


# CreateTrainingJob rejects any AlgorithmSpecification.ContainerArguments member over 256
# chars (ValidationException, unrelated to the S3Uri under test), so this must stay minified.
_TRAIN_SCRIPT = (
    'import glob,os;d="/opt/ml/model";os.makedirs(d,exist_ok=True);'
    'n=sum(sum(1 for _ in open(f)) for f in glob.glob("/opt/ml/input/data/train/*"));'
    'open(d+"/artifact.txt","w").write("total_lines:"+str(n));'
    'print("total_lines="+str(n))'
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI create-training-job with an S3Uri prefix that holds no objects is refused at once with the exact
    ValidationException message although the role can read the bucket, so no job or artifact exists,
    while the same job on an existing object completes and writes its model artifact."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, name_suffix="uri", bucket_name=bucket)

    num_rows = 15
    local_csv = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    try:
        for i in range(num_rows):
            local_csv.write(f"{i},{i * 2}\n")
        local_csv.close()
        _run_aws(ctx, "s3", "cp", local_csv.name, f"s3://{bucket}/train/valid.csv")
    finally:
        os.unlink(local_csv.name)

    job_good = ctx.unique_name("sim2real-train-good-")
    job_bad = ctx.unique_name("sim2real-train-bad-")
    train_image = _train_image_uri(ctx)

    def _payload(job_name, s3_uri, output_prefix):
        return {
            "TrainingJobName": job_name,
            "RoleArn": role_arn,
            "AlgorithmSpecification": {
                "TrainingImage": train_image,
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
                            "S3Uri": s3_uri,
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                }
            ],
            "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/{output_prefix}"},
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            "StoppingCondition": {"MaxRuntimeInSeconds": 900},
            "Tags": [{"Key": "sim2real", "Value": "invalid-s3-input-uri"}],
        }

    _create_training_job_via_cli_with_role_retry(
        ctx, _payload(job_good, f"s3://{bucket}/train/valid.csv", "output-good")
    )

    bad_proc = _create_training_job_via_cli(
        ctx, _payload(job_bad, f"s3://{bucket}/train/does-not-exist.csv", "output-bad")
    )
    assert bad_proc.returncode != 0, (
        "expected CreateTrainingJob to synchronously reject an S3Uri prefix with no objects "
        "under it, but the CLI call succeeded"
    )
    expected_message = _no_s3_objects_message(
        ctx, f"s3://{bucket}/train/does-not-exist.csv", bucket, role_arn, list_denied=False
    )
    # The CLI inserts " (reached max retries: N)" after the operation name when it retried the call
    # first; the rest of the line is AWS's answer.
    stderr = re.sub(r" \(reached max retries: \d+\)", "", bad_proc.stderr.strip(), count=1)
    assert stderr == (
        "aws: [ERROR]: An error occurred (ValidationException) when calling the CreateTrainingJob "
        "operation: "
        f"{expected_message}"
    ), f"expected the exact missing-S3-object rejection, got: {bad_proc.stderr[-1000:]}"

    sm = ctx.client("sagemaker")
    not_found = _client_error(lambda: sm.describe_training_job(TrainingJobName=job_bad))
    assert not_found.get("Code") == "ValidationException", not_found
    assert not_found.get("Message") == "Requested resource not found.", not_found

    s3 = ctx.client("s3")
    listing = s3.list_objects_v2(Bucket=bucket, Prefix="output-bad")
    assert "Contents" not in listing, "no model artifact should have been produced for a rejected job"

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
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "invalid-s3-input-uri"}]}
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
        Tags=[{"Key": "sim2real", "Value": "invalid-s3-input-uri"}],
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
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ecr:GetAuthorizationToken",
                            "ecr:BatchCheckLayerAvailability",
                            "ecr:GetDownloadUrlForLayer",
                            "ecr:BatchGetImage",
                        ],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_training_job_via_cli(ctx, payload, *, timeout_s=180.0, interval_s=10.0):
    """Runs create-training-job via the CLI, retrying only the transient ValidationException a
    just-created role produces before IAM's eventual consistency catches up. Returns the final
    CompletedProcess whether it succeeded or was permanently rejected -- the caller decides
    which outcome is expected."""
    deadline = time.monotonic() + timeout_s
    while True:
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
        transient_role_not_ready = (
            proc.returncode != 0
            and "ValidationException" in proc.stderr
            and ("not authorized" in proc.stderr or "assume role" in proc.stderr.lower())
        )
        if transient_role_not_ready and time.monotonic() < deadline:
            time.sleep(interval_s)
            continue
        return proc


def _create_training_job_via_cli_with_role_retry(ctx, payload, *, timeout_s=180.0, interval_s=10.0):
    proc = _create_training_job_via_cli(ctx, payload, timeout_s=timeout_s, interval_s=interval_s)
    if proc.returncode != 0:
        raise AssertionError(f"create-training-job failed: {proc.stderr[-500:]}")


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict, or raise if fn() unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _read_tar_member_from_s3(ctx, s3_uri, member_name):
    assert s3_uri.startswith("s3://"), f"expected an s3:// URI for the model artifact, got {s3_uri!r}"
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
