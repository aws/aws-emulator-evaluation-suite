"""cli-sagemaker-describe-training-job-status-transitions."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sagemaker-describe-training-job-status-transitions"
GROUP = "cli-workflow"
SERVICES = ["s3", "sagemaker"]

# AWS-owned ECR registry account for the built-in XGBoost algorithm image, one per
# region (the registry itself is region-pinned, not a customer-account literal).
_XGBOOST_IMAGE_ACCOUNTS = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-west-3": "659782779980",
    "sa-east-1": "737474898029",
}
_XGBOOST_TAG = "1.5-1"

# SecondaryStatus values that occur at/after the model artifact is written to S3
# (per docs.aws.amazon.com/sagemaker/latest/APIReference/API_SecondaryStatusTransition.html
# the flow is Starting -> Downloading -> Training -> Uploading -> Completed).
_POST_ARTIFACT_SECONDARY_STATUSES = {"Uploading", "Completed", "MaxRuntimeExceeded", "Failed", "Stopped"}


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI describe-training-job's SecondaryStatus correlates with the model artifact's appearance in S3:
    the artifact is absent while the job is Starting/Downloading/Training and present once Uploading/Completed."""
    require_tools("aws")
    image_uri = _xgboost_image_uri(ctx.region)
    if image_uri is None:
        raise AssertionError(f"no known SageMaker XGBoost built-in-algorithm image for region {ctx.region}")

    bucket, train_key = _create_data_bucket(ctx)
    role_arn = _create_training_role(ctx, bucket, grant_s3_access=True)
    job_name = ctx.unique_name("sim2real-sm-job-")
    output_prefix = "output-root"

    request = _training_job_request(job_name, role_arn, image_uri, bucket, train_key, output_prefix)
    _create_training_job_cli(ctx, request)
    ctx.on_cleanup(lambda: _stop_training_job_ignore_errors(ctx, job_name))

    output_prefix_full = f"{output_prefix}/{job_name}/"
    saw_pre_artifact_absence = False
    terminal = {"Completed", "Failed", "Stopped"}
    deadline = time.monotonic() + 900.0
    described = None
    while time.monotonic() < deadline:
        described = _run_aws(ctx, "sagemaker", "describe-training-job", "--training-job-name", job_name)
        status = described.get("TrainingJobStatus")
        secondary = described.get("SecondaryStatus")
        if secondary not in _POST_ARTIFACT_SECONDARY_STATUSES:
            keys = _list_s3_keys_cli(ctx, bucket, output_prefix_full)
            assert keys == [], (
                f"artifact appeared while SecondaryStatus={secondary!r} (pre-upload): {keys}"
            )
            saw_pre_artifact_absence = True
        if status in terminal:
            break
        time.sleep(2)
    else:
        raise AssertionError(f"training job {job_name} did not reach terminal state in time; last={described}")

    assert described["TrainingJobStatus"] == "Completed", (
        f"training job did not complete: {described.get('TrainingJobStatus')} / {described.get('FailureReason')}"
    )
    assert saw_pre_artifact_absence, "never observed a pre-upload poll to correlate against (job finished too fast)"
    final_keys = _list_s3_keys_cli(ctx, bucket, output_prefix_full)
    assert any(k.endswith("model.tar.gz") for k in final_keys), f"artifact missing after Completed: {final_keys}"


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


def _list_s3_keys_cli(ctx, bucket, prefix):
    out = _run_aws(ctx, "s3api", "list-objects-v2", "--bucket", bucket, "--prefix", prefix)
    if isinstance(out, dict):
        return [o["Key"] for o in out.get("Contents", [])]
    return []


def _xgboost_image_uri(region):
    account = _XGBOOST_IMAGE_ACCOUNTS.get(region)
    if account is None:
        return None
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:{_XGBOOST_TAG}"


def _create_data_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-data-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    rows = [f"{i % 2},{i * 0.5},{i * 1.5}" for i in range(20)]
    csv_body = ("\n".join(rows) + "\n").encode("utf-8")
    key = "train/data.csv"
    s3.put_object(Bucket=bucket, Key=key, Body=csv_body)
    return bucket, key


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_training_role(ctx, bucket_name, *, grant_s3_access):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:*",
    }]
    if grant_s3_access:
        statements.append({
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        })
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    policy_name = ctx.unique_name("sim2real-sm-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _training_job_request(job_name, role_arn, image_uri, bucket, train_key, output_prefix):
    return {
        "TrainingJobName": job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {"TrainingImage": image_uri, "TrainingInputMode": "File"},
        "HyperParameters": {"objective": "reg:squarederror", "num_round": "3"},
        "InputDataConfig": [{
            "ChannelName": "train",
            "DataSource": {
                "S3DataSource": {
                    "S3DataType": "S3Prefix",
                    "S3Uri": f"s3://{bucket}/{train_key}",
                    "S3DataDistributionType": "FullyReplicated",
                }
            },
            "ContentType": "text/csv",
            "CompressionType": "None",
        }],
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/{output_prefix}"},
        "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        "StoppingCondition": {"MaxRuntimeInSeconds": 900},
        "ProfilerConfig": {"DisableProfiler": True},
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }


def _create_training_job_cli(ctx, request, *, retries=8, delay_s=10.0):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(request, f)
        path = f.name
    try:
        last_stderr = ""
        for _ in range(retries):
            proc = _run_shell(
                ctx,
                ["aws", "--output", "json", "sagemaker",
                 "create-training-job", "--cli-input-json", f"file://{path}"],
                timeout_s=30.0,
                check=False,
            )
            if proc.returncode == 0:
                return
            last_stderr = proc.stderr
            if "ValidationException" in proc.stderr:
                time.sleep(delay_s)
                continue
            raise AssertionError(f"create-training-job failed: {proc.stderr[-500:]}")
        raise AssertionError(f"create-training-job failed after retries: {last_stderr[-500:]}")
    finally:
        os.unlink(path)


def _stop_training_job_ignore_errors(ctx, job_name):
    sm = ctx.client("sagemaker")
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
