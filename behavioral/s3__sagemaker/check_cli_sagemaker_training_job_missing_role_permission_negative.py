"""cli-sagemaker-training-job-missing-role-permission-negative."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-sagemaker-training-job-missing-role-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

# The AWS-managed ECR registry account that hosts the built-in XGBoost algorithm image
# differs per region (it is not the caller's own account), so this table is a genuine
# region-pinned constant rather than a hardcoded-region shortcut.
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws sagemaker create-training-job` with a role lacking S3 access to the input fails
    synchronously with an S3 access-denial error, creating no job and no artifact, while a role with
    S3 access (positive control) trains to completion."""
    require_tools("aws")
    image_uri = _xgboost_image_uri(ctx.region)
    if image_uri is None:
        raise AssertionError(f"no known SageMaker XGBoost built-in-algorithm image for region {ctx.region}")

    bucket, train_key = _create_data_bucket(ctx)
    output_prefix = "output-root"

    # ---- negative: role trusted by SageMaker but with NO s3 permissions at all ----
    bad_role_arn = _create_training_role(ctx, bucket, grant_s3_access=False)
    bad_job_name = ctx.unique_name("sim2real-sm-badjob-")
    bad_request = _training_job_request(bad_job_name, bad_role_arn, image_uri, bucket, train_key, output_prefix)

    denial_stderr = _create_training_job_cli_expect_denial(ctx, bad_request)
    assert "ListBucket" in denial_stderr or "AccessDenied" in denial_stderr or "not authorized" in denial_stderr, (
        f"expected an S3-access-denial ValidationException, got: {denial_stderr!r}"
    )

    listing = _run_aws(ctx, "sagemaker", "list-training-jobs", "--name-contains", bad_job_name)
    summaries = listing.get("TrainingJobSummaries", []) if isinstance(listing, dict) else []
    assert summaries == [], f"training job should never have been created, found: {summaries}"

    bad_job_prefix = f"{output_prefix}/{bad_job_name}/"
    bad_keys = _list_s3_keys_cli(ctx, bucket, bad_job_prefix)
    assert bad_keys == [], f"artifact should never have been written, found: {bad_keys}"

    # ---- positive control: identical setup, role WITH s3 access ----
    good_role_arn = _create_training_role(ctx, bucket, grant_s3_access=True)
    good_job_name = ctx.unique_name("sim2real-sm-goodjob-")
    good_request = _training_job_request(good_job_name, good_role_arn, image_uri, bucket, train_key, output_prefix)
    _create_training_job_cli(ctx, good_request)
    ctx.on_cleanup(lambda: _stop_training_job_ignore_errors(ctx, good_job_name))

    good_described = _poll_training_job(ctx, good_job_name, timeout_s=900.0, interval_s=15.0)
    assert good_described["TrainingJobStatus"] == "Completed", (
        f"positive control did not complete: {good_described.get('TrainingJobStatus')} / "
        f"{good_described.get('FailureReason')}"
    )
    good_job_prefix = f"{output_prefix}/{good_job_name}/"
    good_keys = _list_s3_keys_cli(ctx, bucket, good_job_prefix)
    assert any(k.endswith("model.tar.gz") for k in good_keys), (
        f"positive control artifact missing: {good_keys}"
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
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )
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


def _create_training_job_cli_expect_denial(ctx, request, *, retries=10, delay_s=8.0):
    """Submit a training-job request expected to be rejected synchronously by the
    S3-reachability preflight. Retries only on transient IAM role-propagation errors
    (the role/trust not yet visible to STS); any other failure -- in particular the
    S3 access-denial ValidationException we're testing for -- is returned immediately."""
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
                raise AssertionError(
                    "create-training-job unexpectedly succeeded with a role lacking S3 access "
                    f"(job {request['TrainingJobName']} was created)"
                )
            stderr = proc.stderr
            if "sts:AssumeRole" in stderr or "Unable to assume role" in stderr or "Could not assume role" in stderr:
                last_stderr = stderr
                time.sleep(delay_s)
                continue
            return stderr
        raise AssertionError(f"role trust never propagated to STS in time: {last_stderr[-2000:]}")
    finally:
        os.unlink(path)


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
        raise AssertionError(f"create-training-job failed after retries: {last_stderr[-2000:]}")
    finally:
        os.unlink(path)


def _poll_training_job(ctx, job_name, *, timeout_s=900.0, interval_s=15.0):
    terminal = {"Completed", "Failed", "Stopped"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _run_aws(ctx, "sagemaker", "describe-training-job", "--training-job-name", job_name)
        if last.get("TrainingJobStatus") in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"training job {job_name} did not reach terminal state in {timeout_s}s; last={last}")


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
