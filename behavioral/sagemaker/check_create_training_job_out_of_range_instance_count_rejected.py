"""create-training-job-out-of-range-instance-count-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-training-job-out-of-range-instance-count-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob with ResourceConfig.InstanceCount=0 is rejected with a validation
    error and never creates a job record, while the same request with InstanceCount=1
    (the smallest valid value) is accepted and actually launches."""
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    role_arn = _create_sagemaker_exec_role(ctx)
    bucket_name = ctx.unique_name("sim2real-sm-out-")
    _create_bucket(ctx, s3, bucket_name)
    # A deep-learning-container image: the same account id resolves in every region, unlike
    # the built-in algorithms (e.g. linear-learner), which live behind a different registry
    # account per region.
    training_image = f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:1.12.1-cpu-py38"

    def _make_request(name: str, instance_count: int) -> dict:
        return dict(
            TrainingJobName=name,
            RoleArn=role_arn,
            AlgorithmSpecification={
                "TrainingImage": training_image,
                "TrainingInputMode": "File",
            },
            ResourceConfig={
                "InstanceType": "ml.m5.large",
                "InstanceCount": instance_count,
                "VolumeSizeInGB": 1,
            },
            OutputDataConfig={"S3OutputPath": f"s3://{bucket_name}/out"},
            StoppingCondition={"MaxRuntimeInSeconds": 120},
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    # -- negative: InstanceCount=0 is out of range for a real training job
    bad_name = ctx.unique_name("sim2real-sm-tj-bad-")
    err = _error(
        lambda: _retry_role_propagation(
            lambda: sm.create_training_job(**_make_request(bad_name, 0))
        )
    )
    assert err.get("Code") == "ValidationException", f"expected ValidationException, got {err}"
    assert err.get("Message") == "InstanceType and InstanceCount greater than 0 must be specified", (
        f"unexpected ValidationException message: {err}"
    )
    # Real AWS surfaces "cannot assume role" as the SAME ValidationException code as the
    # out-of-range InstanceCount rejection under test, so the code alone cannot tell them
    # apart. _retry_role_propagation already retries the role-assumption message away; this
    # guards against it slipping through as a false pass if propagation is still incomplete.
    assert "assume role" not in err.get("Message", "").lower(), (
        f"got ValidationException, but for role assumption, not the out-of-range "
        f"InstanceCount under test: {err}"
    )

    # effect absent: no training job record was created under that name. DescribeTrainingJob
    # has no ResourceNotFound case for SageMaker training jobs: a name that was never created
    # surfaces as ValidationException.
    not_found = _error(lambda: sm.describe_training_job(TrainingJobName=bad_name))
    assert not_found.get("Code") == "ValidationException", (
        f"expected DescribeTrainingJob for a never-created job to fail with "
        f"ValidationException, got {not_found}"
    )
    assert not_found.get("Message") == "Requested resource not found.", (
        f"unexpected not-found message: {not_found}"
    )

    # -- positive control: same shape of request, InstanceCount=1 is accepted
    good_name = ctx.unique_name("sim2real-sm-tj-good-")
    resp = _retry_role_propagation(
        lambda: sm.create_training_job(**_make_request(good_name, 1))
    )
    assert resp["TrainingJobArn"].endswith(f"training-job/{good_name}")

    def _stop_and_forget():
        try:
            sm.stop_training_job(TrainingJobName=good_name)
        except ClientError as exc:
            # ValidationException: the job already reached a terminal status.
            if exc.response["Error"]["Code"] != "ValidationException":
                raise

    ctx.on_cleanup(_stop_and_forget)

    status = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status = sm.describe_training_job(TrainingJobName=good_name)["TrainingJobStatus"]
        if status in ("InProgress", "Failed", "Completed", "Stopping", "Stopped"):
            break
        time.sleep(5)
    assert status in ("InProgress", "Failed", "Completed", "Stopping", "Stopped"), (
        f"training job never left a pending state, last status={status}"
    )


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
    """IAM role/policy propagation is eventually consistent, and real AWS surfaces a
    not-yet-assumable role as ValidationException (the SAME code CreateTrainingJob uses
    for an out-of-range InstanceCount) with a "cannot assume role" message, so the retry
    must match on the message, not the code."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            message = exc.response.get("Error", {}).get("Message", "")
            if "assume role" in message.lower():
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_sagemaker_exec_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    return role_arn


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
