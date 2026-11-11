"""create-training-job-invalid-instance-count-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-training-job-invalid-instance-count-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob with ResourceConfig.InstanceCount=0 is rejected synchronously: the API
    shape declares a minimum of 0, but the service requires at least 1 instance to run a job.
    """
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    role_arn = _create_sagemaker_role(ctx)
    bucket_name = ctx.unique_name("sim2real-tj-out-")
    _create_bucket(ctx, s3, bucket_name)
    bucket_path = f"s3://{bucket_name}/output"

    def _request(name: str, instance_count: int) -> dict:
        return dict(
            TrainingJobName=name,
            RoleArn=role_arn,
            AlgorithmSpecification={
                "TrainingImage": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:1.12.1-cpu-py38",
                "TrainingInputMode": "File",
            },
            ResourceConfig={
                "InstanceType": "ml.m5.large",
                "InstanceCount": instance_count,
                "VolumeSizeInGB": 10,
            },
            OutputDataConfig={"S3OutputPath": bucket_path},
            StoppingCondition={"MaxRuntimeInSeconds": 60},
        )

    # --- negative: InstanceCount=0 is structurally within the shape's declared range (min 0)
    # but is not a usable instance count ---
    bad_job_name = ctx.unique_name("sim2real-tj-bad-")
    code, message = _error(lambda: sm.create_training_job(**_request(bad_job_name, 0)))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "InstanceType and InstanceCount greater than 0 must be specified", (
        f"unexpected ValidationException message: {message!r}"
    )

    # effect absent: the training job was never created (DescribeTrainingJob does not declare
    # ResourceNotFound; a nonexistent TrainingJobName surfaces as ValidationException instead)
    describe_code, describe_message = _error(lambda: sm.describe_training_job(TrainingJobName=bad_job_name))
    assert describe_code == "ValidationException", f"expected ValidationException, got {describe_code!r}"
    assert describe_message == "Requested resource not found.", (
        f"unexpected not-found message: {describe_message!r}"
    )

    # --- positive control: InstanceCount=1 is accepted and the job is created ---
    good_job_name = ctx.unique_name("sim2real-tj-good-")
    resp = _create_training_job_with_role_retry(sm, _request(good_job_name, 1))

    def _cleanup_training_job():
        from botocore.exceptions import ClientError

        # Stop answers ValidationException once the job is terminal; delete is refused with
        # ResourceInUse (or ValidationException) while the job is still stopping, so that is
        # retried to a deadline.
        try:
            sm.stop_training_job(TrainingJobName=good_job_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ValidationException":
                raise
        deadline = time.monotonic() + 300
        while True:
            try:
                sm.delete_training_job(TrainingJobName=good_job_name)
                return
            except ClientError as e:
                error = e.response["Error"]
                message = error.get("Message", "").lower()
                if error["Code"] == "ResourceNotFound" or (
                    error["Code"] == "ValidationException" and "not found" in message
                ):
                    return
                retryable = error["Code"] in ("ResourceInUse", "ValidationException")
                if not retryable or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup_training_job)
    assert resp["TrainingJobArn"].endswith(f"training-job/{good_job_name}")

    # terminal assertion is an INDEPENDENT read (DescribeTrainingJob), not the mutating
    # call's own response: the job must actually be running under the requested shape.
    described = sm.describe_training_job(TrainingJobName=good_job_name)
    assert described["ResourceConfig"]["InstanceCount"] == 1, (
        f"expected the created job's own ResourceConfig.InstanceCount to be 1, "
        f"got {described['ResourceConfig'].get('InstanceCount')!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_training_job_with_role_retry(sm, request: dict, deadline_s: float = 60.0, interval_s: float = 5.0) -> dict:
    """Retry CreateTrainingJob while the just-created execution role is still propagating.

    IAM role/policy attachment is eventually consistent, and SageMaker resolves the role
    synchronously at CreateTrainingJob time, so the first attempt(s) right after role
    creation can be rejected for a reason that has nothing to do with the request shape.
    The retry is bounded: it re-raises once the deadline passes.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return sm.create_training_job(**request)
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreateTrainingJob synchronously verifies the role can pull the training image and write
    # to the output bucket, so the role needs real ECR + S3 permissions.
    for policy_arn in (
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p))
    return arn


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    # us-east-1 is S3's own special case: CreateBucketConfiguration is rejected there and
    # required everywhere else, so this branches on the region S3 itself special-cases.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
