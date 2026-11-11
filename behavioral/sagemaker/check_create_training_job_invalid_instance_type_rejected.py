"""create-training-job-invalid-instance-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-training-job-invalid-instance-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob with a syntactically invalid InstanceType is rejected with a validation error."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_bucket(ctx)
    output_path = f"s3://{bucket}/output"
    image_uri = f"683313688378.dkr.ecr.{ctx.region}.amazonaws.com/sim2real-behavioral-mock:latest"

    bad_job_name = ctx.unique_name("sim2real-behav-train-bad-")
    code, message = _error(lambda: sm.create_training_job(
        TrainingJobName=bad_job_name,
        RoleArn=role_arn,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        OutputDataConfig={"S3OutputPath": output_path},
        ResourceConfig={
            "InstanceType": "ml.totally.bogus",
            "InstanceCount": 1,
            "VolumeSizeInGB": 10,
        },
        StoppingCondition={"MaxRuntimeInSeconds": 3600},
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'ml.totally.bogus' at 'resourceConfig.instanceType' "
        "failed to satisfy constraint: Member must be a supported instance type"
    ), f"unexpected ValidationException message: {message!r}"

    # effect absent: the training job was never created. DescribeTrainingJob has no
    # ResourceNotFound of its own; a name that was never created surfaces as ValidationException.
    describe_code, describe_message = _error(lambda: sm.describe_training_job(TrainingJobName=bad_job_name))
    assert describe_code == "ValidationException", f"expected ValidationException, got {describe_code!r}"
    assert describe_message == "Requested resource not found.", (
        f"unexpected not-found message: {describe_message!r}"
    )

    # positive control: the identical request with a real instance type is accepted
    good_job_name = ctx.unique_name("sim2real-behav-train-good-")
    resp = _retry_role_propagation(lambda: sm.create_training_job(
        TrainingJobName=good_job_name,
        RoleArn=role_arn,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        OutputDataConfig={"S3OutputPath": output_path},
        ResourceConfig={
            "InstanceType": "ml.m5.large",
            "InstanceCount": 1,
            "VolumeSizeInGB": 10,
        },
        StoppingCondition={"MaxRuntimeInSeconds": 120},
    ))
    ctx.on_cleanup(lambda: _best_effort_stop(sm, good_job_name))
    assert resp["TrainingJobArn"].endswith(good_job_name), (
        f"expected TrainingJobArn to end with {good_job_name!r}, got {resp['TrainingJobArn']!r}"
    )

    # terminal read: independent DescribeTrainingJob confirms the accepted job actually
    # progressed at the destination, not just that CreateTrainingJob echoed a 200
    status = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        status = sm.describe_training_job(TrainingJobName=good_job_name)["TrainingJobStatus"]
        if status in ("InProgress", "Failed", "Completed", "Stopping", "Stopped"):
            break
        time.sleep(5.0)
    assert status in ("InProgress", "Failed", "Completed", "Stopping", "Stopped"), (
        f"expected the accepted training job to leave its pending state, last status={status!r}"
    )


# ===== helpers =====

def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _best_effort_stop(sm, job_name):
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # ValidationException: the job already reached a terminal status.
        if exc.response["Error"]["Code"] != "ValidationException":
            raise


def _retry_role_propagation(fn, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-smrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1.0)
    return role_arn


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-bkt-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
