"""create-training-job-invalid-role-arn-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-training-job-invalid-role-arn-denied"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob referencing a role ARN that names no real IAM role is
    rejected before any training job is created, while an otherwise identical
    request using a real, assumable role succeeds."""
    sm = ctx.client("sagemaker")
    account = ctx.client("sts").get_caller_identity()["Account"]
    image = f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/sklearn-inference:0.23-1-cpu-py3"

    bogus_role = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-noexist-')}"
    bad_job_name = ctx.unique_name("sim2real-behav-tj-bad-")

    def _create_bad():
        sm.create_training_job(
            TrainingJobName=bad_job_name,
            RoleArn=bogus_role,
            AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 10},
            OutputDataConfig={"S3OutputPath": f"s3://sagemaker-sample-files/{bad_job_name}"},
            StoppingCondition={"MaxRuntimeInSeconds": 600},
        )

    code, message = _error(_create_bad)
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    expected = (
        f"Could not assume role {bogus_role}. Please ensure that the role exists and allows "
        "principal 'sagemaker.amazonaws.com' to assume the role."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    absent_code, absent_message = _error(
        lambda: sm.describe_training_job(TrainingJobName=bad_job_name)
    )
    assert absent_code == "ValidationException", (
        f"training job should never have been created, got {absent_code!r} on describe "
        f"({absent_message!r})"
    )
    assert absent_message == "Requested resource not found.", (
        f"expected a not-found message, got {absent_message!r}"
    )

    role_arn, role_name = _create_execution_role(ctx)
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    good_job_name = ctx.unique_name("sim2real-behav-tj-good-")
    _create_training_job_with_role_propagation_retry(
        sm,
        TrainingJobName=good_job_name,
        RoleArn=role_arn,
        AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 10},
        OutputDataConfig={"S3OutputPath": f"s3://sagemaker-sample-files/{good_job_name}"},
        StoppingCondition={"MaxRuntimeInSeconds": 600},
    )
    ctx.on_cleanup(lambda: _stop_and_delete_training_job(ctx, good_job_name))

    described = sm.describe_training_job(TrainingJobName=good_job_name)
    assert described["RoleArn"] == role_arn, (
        f"expected the control job to have been created with {role_arn!r}, got {described.get('RoleArn')!r}"
    )
    assert described["TrainingJobStatus"] in ("InProgress", "Completed", "Failed", "Stopping", "Stopped"), (
        f"expected a live-job status, got {described['TrainingJobStatus']!r}"
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


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-tjrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn, role_name


def _is_role_not_ready(exc: ClientError) -> bool:
    code = exc.response["Error"]["Code"]
    message = exc.response["Error"].get("Message", "")
    return code == "ResourceNotFound" or (
        code == "ValidationException" and "assume role" in message.lower()
    )


def _create_training_job_with_role_propagation_retry(sm, *, timeout_s=60.0, **kwargs):
    """IAM trust/attachment propagation is eventually consistent, and there is nothing
    observable to poll before SageMaker can assume a just-created role. Retry only the
    role-not-ready errors that propagation delay produces, bounded by a deadline; let
    every other error surface as-is."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            sm.create_training_job(**kwargs)
            return
        except ClientError as exc:
            if _is_role_not_ready(exc):
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise last_err


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    for call in (
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise


def _stop_and_delete_training_job(ctx, job_name):
    sm = ctx.client("sagemaker")
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # ValidationException: the job already reached a terminal status.
        if exc.response["Error"]["Code"] != "ValidationException":
            raise
    deadline = time.monotonic() + 300
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
        if status in ("Completed", "Failed", "Stopped"):
            break
        time.sleep(2)
    try:
        sm.delete_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] != "ValidationException" or "not found" not in error.get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
