"""training-job-empty-vs-absent-hyperparameter-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "training-job-empty-vs-absent-hyperparameter-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob accepts an empty-string hyperparameter, but DescribeTrainingJob omits that
    key exactly as it omits one never sent, while a non-empty value round-trips unchanged; a target
    echoing "" back diverges from AWS."""
    sm = ctx.client("sagemaker")

    role_arn = _create_sagemaker_execution_role(ctx)

    job_name = ctx.unique_name("sim2real-hp-job-")
    training_image = _linear_learner_image(ctx.region)
    output_bucket = ctx.unique_name("sim2real-hp-out-")

    hyperparameters = {
        "empty_hp": "",
        "present_hp": "42",
    }

    def _create():
        return sm.create_training_job(
            TrainingJobName=job_name,
            HyperParameters=hyperparameters,
            AlgorithmSpecification={"TrainingImage": training_image, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            OutputDataConfig={"S3OutputPath": f"s3://{output_bucket}/output/"},
            ResourceConfig={
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeSizeInGB": 1,
            },
            StoppingCondition={"MaxRuntimeInSeconds": 120},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    # IAM role/trust propagation can lag by up to ~15-20s after CreateRole.
    _retry_until_role_usable(_create, timeout_s=45.0)
    ctx.on_cleanup(lambda: _teardown_training_job(sm, job_name))

    described = sm.describe_training_job(TrainingJobName=job_name)
    hp = described["HyperParameters"]

    assert "empty_hp" not in hp, (
        f"an explicit empty-string hyperparameter was preserved as a distinct key -- "
        f"real AWS drops it, treating it exactly like a key that was never supplied: {hp!r}"
    )
    assert "present_hp" in hp and hp["present_hp"] == "42", (
        f"present_hp should read back as '42', got {hp.get('present_hp')!r}"
    )
    assert "absent_hp" not in hp, f"a hyperparameter never supplied appeared in the response: {hp!r}"


# SageMaker's built-in "linear-learner" algorithm image lives in a different,
# region-pinned ECR account per region -- these are AWS's own account ids, not ours.
_LINEAR_LEARNER_REGISTRY = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
    "eu-central-1": "664544806723",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-south-1": "991648021394",
    "ca-central-1": "469771592824",
}


def _linear_learner_image(region: str) -> str:
    account = _LINEAR_LEARNER_REGISTRY.get(region)
    if not account:
        raise AssertionError(
            f"no known linear-learner built-in algorithm registry account for "
            f"region {region!r}; extend _LINEAR_LEARNER_REGISTRY to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _create_sagemaker_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # Register cleanup in create order so LIFO teardown detaches before deleting.
    def _delete_role():
        iam.delete_role(RoleName=role_name)

    def _detach_policy():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    ctx.on_cleanup(_detach_policy)
    return role_arn


def _retry_until_role_usable(create_fn, *, timeout_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return create_fn()
        except Exception as exc:  # noqa: BLE001 - retry on any transient IAM-propagation error
            last_exc = exc
            message = str(exc).lower()
            if (
                "not authorized" in message
                or "cannot be assumed" in message
                or "could not assume role" in message
            ):
                time.sleep(3.0)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever attempting create_fn"
    raise last_exc


def _training_job_gone(exc) -> bool:
    """SageMaker reports a missing training job as ValidationException 'Requested resource not found'."""
    err = exc.response["Error"]
    return err["Code"] == "ResourceNotFound" or (
        err["Code"] == "ValidationException" and "not found" in err.get("Message", "").lower()
    )


def _teardown_training_job(sm, job_name: str) -> None:
    """Stop the job, wait for a terminal status and delete it; a job already gone or Deleting
    returns, any other failure raises. Bounded at 300 s."""
    deadline = time.monotonic() + 300.0
    stop_requested = False
    while True:
        try:
            status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
        except ClientError as exc:
            if _training_job_gone(exc):
                return
            raise
        if status == "Deleting":
            return
        if status in ("Completed", "Failed", "Stopped"):
            break
        if status == "InProgress" and not stop_requested:
            sm.stop_training_job(TrainingJobName=job_name)
            stop_requested = True
        if time.monotonic() >= deadline:
            raise AssertionError(f"training job {job_name} still {status} after 300s of teardown")
        time.sleep(2)
    try:
        sm.delete_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if not _training_job_gone(exc):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
