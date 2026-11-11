"""create-training-job-negative-instance-count-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-training-job-negative-instance-count-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob refuses ResourceConfig.InstanceCount=-1 (sent with client-side validation off so it
    reaches SageMaker) with ValidationException and its exact message and persists no job, while the same request
    with InstanceCount=1 is accepted and describes with InstanceCount 1.
    """
    sm = ctx.client("sagemaker")
    raw_sm = ctx.client("sagemaker", config=Config(parameter_validation=False))
    s3 = ctx.client("s3")
    role_arn = _create_exec_role(ctx)
    bucket_name = ctx.unique_name("sim2real-tj-out-")
    _create_bucket(ctx, s3, bucket_name)
    training_image = f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:1.12.1-cpu-py38"

    def _request(name: str, instance_count: int) -> dict:
        return dict(
            TrainingJobName=name,
            RoleArn=role_arn,
            AlgorithmSpecification={"TrainingImage": training_image, "TrainingInputMode": "File"},
            OutputDataConfig={"S3OutputPath": f"s3://{bucket_name}/out/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": instance_count, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 60},
        )

    # Only InstanceCount varies between the two calls below, so a ValidationException on the
    # bad one can only be about the negative count — not the image, the role or the bucket.
    bad_name = ctx.unique_name("sim2real-tj-bad-")
    code, message = _error(
        lambda: _retry_role_propagation(lambda: raw_sm.create_training_job(**_request(bad_name, -1)))
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value '-1' at 'resourceConfig.instanceCount' failed to "
        "satisfy constraint: Member must have value greater than or equal to 0"
    ), f"unexpected ValidationException message: {message!r}"

    listed = [
        j for j in sm.list_training_jobs(NameContains=bad_name)["TrainingJobSummaries"]
        if j["TrainingJobName"] == bad_name
    ]
    assert not listed, f"a training job with a negative instance count was persisted: {listed}"

    good_name = ctx.unique_name("sim2real-tj-good-")
    _retry_role_propagation(lambda: sm.create_training_job(**_request(good_name, 1)))
    ctx.on_cleanup(lambda: _safe(lambda: sm.stop_training_job(TrainingJobName=good_name)))
    desc = sm.describe_training_job(TrainingJobName=good_name)
    assert desc["TrainingJobName"] == good_name, f"expected {good_name}, got {desc['TrainingJobName']}"
    assert desc["ResourceConfig"]["InstanceCount"] == 1, (
        f"expected InstanceCount 1, got {desc['ResourceConfig']['InstanceCount']}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a request real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


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
    # CreateTrainingJob synchronously verifies the role can pull the training image and write
    # to the output bucket, so the role needs real ECR + S3 permissions (SageMakerFullAccess
    # alone is not enough for that synchronous check to pass).
    for policy_arn in (
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
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


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))


def _empty_and_delete_bucket(s3, bucket_name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Poll a call that depends on a freshly-created IAM role until IAM's eventual
    consistency window closes, rather than a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
