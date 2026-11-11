"""automl-job-server-side-orchestration-progress."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automl-job-server-side-orchestration-progress"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateAutoMLJobV2 progresses autonomously through candidate generation, observable
    purely via repeated DescribeAutoMLJobV2 status polling with no further client action
    beyond the initial create call."""
    sm = ctx.client("sagemaker")
    role_arn = _create_exec_role(ctx)
    bucket = _create_scratch_bucket(ctx)
    s3 = ctx.client("s3")

    rows = ["feature1,feature2,target"]
    for i in range(600):  # AutoML V2 requires >= 500 rows: "Dataset is not large enough"
        rows.append(f"{i},{i * 2},{i * 3}")
    s3.put_object(Bucket=bucket, Key="train/data.csv", Body="\n".join(rows).encode())

    job_name = ctx.unique_name("sim2real-automl-")
    create_kwargs = dict(
        AutoMLJobName=job_name,
        AutoMLJobInputDataConfig=[
            {
                "ChannelType": "training",
                "ContentType": "text/csv;header=present",
                "CompressionType": "None",
                "DataSource": {
                    "S3DataSource": {"S3DataType": "S3Prefix", "S3Uri": f"s3://{bucket}/train/"}
                },
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/automl-output/"},
        AutoMLJobObjective={"MetricName": "MSE"},
        AutoMLProblemTypeConfig={
            "TabularJobConfig": {
                "TargetAttributeName": "target",
                "Mode": "ENSEMBLING",
                "ProblemType": "Regression",
                "CompletionCriteria": {
                    "MaxCandidates": 1,
                    "MaxRuntimePerTrainingJobInSeconds": 600,
                    "MaxAutoMLJobRuntimeInSeconds": 2400,
                },
            }
        },
        RoleArn=role_arn,
    )
    _create_auto_ml_job_with_role_retry(sm, create_kwargs)
    ctx.on_cleanup(lambda: _safe(lambda: sm.stop_auto_ml_job(AutoMLJobName=job_name)))

    observed = set()
    observed_secondary = set()
    final_status = None
    left = ctx.time_left()
    timeout = 2700 if left is None else max(1.0, min(2700, left - 5.0))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        desc = sm.describe_auto_ml_job_v2(AutoMLJobName=job_name)
        status = desc["AutoMLJobStatus"]
        observed.add(status)
        observed_secondary.add(desc["AutoMLJobSecondaryStatus"])
        if status in ("Completed", "Failed", "Stopped"):
            final_status = status
            break
        time.sleep(2)

    assert final_status is not None, f"AutoML job never reached a terminal status; observed: {observed}"
    assert "InProgress" in observed, (
        f"job reached {final_status} without ever being observed InProgress (statuses seen: "
        f"{observed}) -- this cannot distinguish real async orchestration from a target that "
        f"completes the job synchronously inside CreateAutoMLJobV2"
    )
    assert len(observed_secondary) >= 2, (
        f"expected the job to visibly traverse multiple orchestration phases (candidate "
        f"generation, model tuning, etc.) via AutoMLJobSecondaryStatus, but only observed "
        f"{observed_secondary} -- a target that jumps straight to the terminal secondary status "
        f"is not demonstrating server-side orchestration progress"
    )
    assert final_status == "Completed", f"expected the AutoML job to complete, got {final_status}"


# ===== helpers =====
def _safe(fn) -> None:
    """Stop the job; ValidationException means it already reached a terminal status."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "ValidationException"):
            raise


def _create_auto_ml_job_with_role_retry(sm, create_kwargs: dict) -> None:
    """CreateAutoMLJobV2 with bounded retry on IAM role propagation (the classic
    "role cannot be assumed / is not authorized" race right after CreateRole)."""
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            sm.create_auto_ml_job_v2(**create_kwargs)
            return
        except ClientError as exc:
            msg = str(exc)
            if "role" in msg.lower() and (
                "not authorized" in msg.lower()
                or "cannot be assumed" in msg.lower()
                or "could not assume" in msg.lower()
                or "does not have" in msg.lower()
            ):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise last_exc


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    ctx.on_cleanup(lambda: _delete_exec_role(ctx, role_name))
    return role_arn


def _delete_exec_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-").lower().replace("_", "-").rstrip("-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    # A stopping job can still upload output, so retry an emptied bucket that refills.
    deadline = time.monotonic() + 60
    while True:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
                if keys:
                    errors = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if errors:
                        raise AssertionError(f"could not empty bucket {bucket}: {errors[:3]!r}")
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
