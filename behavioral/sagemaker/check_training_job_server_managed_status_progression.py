"""training-job-server-managed-status-progression."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "training-job-server-managed-status-progression"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeTrainingJob shows the server driving a /bin/false job from InProgress to Failed with
    the exact FailureReason and no client calls beyond polling, proving an async transition."""
    sm = ctx.client("sagemaker")
    role_arn = _create_exec_role(ctx)
    bucket = _create_scratch_bucket(ctx)

    job_name = ctx.unique_name("sim2real-tj-")
    _create_training_job_with_role_retry(
        sm,
        TrainingJobName=job_name,
        RoleArn=role_arn,
        AlgorithmSpecification={
            "TrainingImage": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:1.12.1-cpu-py38",
            "TrainingInputMode": "File",
            "ContainerEntrypoint": ["/bin/false"],
        },
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 600},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _stop_if_in_progress(sm, job_name))

    observed_statuses = set()
    final = None
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        status = desc["TrainingJobStatus"]
        observed_statuses.add(status)
        if status in ("Completed", "Failed", "Stopped"):
            final = desc
            break
        time.sleep(5)

    assert final is not None, f"training job never reached a terminal status: {observed_statuses}"
    assert "InProgress" in observed_statuses, (
        f"expected to observe the server-driven InProgress transition before the terminal "
        f"read (proving async progression, not a synchronous resolution); observed only: "
        f"{observed_statuses}"
    )
    assert final["TrainingJobStatus"] == "Failed", (
        f"expected the /bin/false entrypoint to fail the job, got {final['TrainingJobStatus']}"
    )
    assert final.get("FailureReason") == "AlgorithmError: , exit code: 1", (
        f"unexpected FailureReason for the /bin/false job: {final.get('FailureReason')!r}"
    )


def _create_training_job_with_role_retry(sm, **kwargs):
    """New IAM roles can take a few seconds to propagate before SageMaker can assume them;
    retry on the role-not-assumable error for a bounded window rather than sleeping a fixed
    duration before the call."""
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as exc:
            message = str(exc).lower()
            if "assume" in message and "role" in message:
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


# ===== helpers =====
def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _stop_if_in_progress(sm, job_name: str) -> None:
    """StopTrainingJob is refused on a job already in a terminal status, so stop only a running one."""
    try:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "ResourceNotFound" or (
            error["Code"] == "ValidationException" and error.get("Message") == "Requested resource not found."
        ):
            return
        raise
    if status == "InProgress":
        _safe(lambda: sm.stop_training_job(TrainingJobName=job_name))


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    ctx.on_cleanup(lambda: _delete_exec_role(ctx, role_name))
    return role_arn


def _delete_exec_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
