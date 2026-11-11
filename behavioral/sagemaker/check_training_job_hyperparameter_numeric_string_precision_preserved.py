"""training-job-hyperparameter-numeric-string-precision-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "training-job-hyperparameter-numeric-string-precision-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]

# Built-in "linear-learner" algorithm image account IDs, stable across years, one per
# region. See https://docs.aws.amazon.com/sagemaker/latest/dg/linear-learner.html
# CreateTrainingJob validates ECR pull access for TrainingImage synchronously (it
# rejects with ValidationException before the job is ever created if the image is not
# pullable), so a made-up placeholder image never reaches DescribeTrainingJob at all --
# a real, publicly-pullable built-in image is required just to get the job created.
_LINEAR_LEARNER_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "eu-west-2": "644912444149",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-south-1": "991648021394",
    "sa-east-1": "855470959533",
    "ca-central-1": "469771592824",
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A high-precision decimal string passed as a HyperParameters value in
    CreateTrainingJob is returned unmodified (no float rounding/truncation) by
    DescribeTrainingJob -- HyperParameters values are opaque strings, not numbers."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)

    job_name = ctx.unique_name("sim2real-sm-hp-")
    high_precision_value = "3.14159265358979323846264338327950288419716939937510"
    bucket = ctx.unique_name("sim2real-sm-hp-out-").lower()
    training_image = _linear_learner_image(ctx.region)

    _wait_for_role_usable(
        ctx,
        role_arn,
        job_name,
        high_precision_value,
        f"s3://{bucket}/output/",
        training_image,
    )
    ctx.on_cleanup(lambda: _stop_and_delete_training_job(sm, job_name))

    desc = sm.describe_training_job(TrainingJobName=job_name)
    actual = desc["HyperParameters"].get("pi_estimate")
    assert actual == high_precision_value, (
        f"pi_estimate hyperparameter not preserved verbatim: {actual!r} != {high_precision_value!r}"
    )

    # The job is real and billable once created; stop it immediately -- the
    # hyperparameters are already durably persisted and returned by CreateTrainingJob,
    # so nothing past this point needs the training run to keep going.
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except Exception:
        pass


def _linear_learner_image(region: str) -> str:
    account = _LINEAR_LEARNER_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no known built-in linear-learner registry account mapped for region {region!r}"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-hp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for call in (
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role_arn


def _wait_for_role_usable(ctx, role_arn, job_name, hp_value, output_prefix, training_image):
    """IAM role trust propagation is eventually consistent; poll CreateTrainingJob
    itself (the observable condition we actually need) until SageMaker accepts the
    role, rather than sleeping a fixed duration."""
    from botocore.exceptions import ClientError

    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            sm.create_training_job(
                TrainingJobName=job_name,
                RoleArn=role_arn,
                AlgorithmSpecification={
                    "TrainingImage": training_image,
                    "TrainingInputMode": "File",
                },
                HyperParameters={"pi_estimate": hp_value},
                OutputDataConfig={"S3OutputPath": output_prefix},
                ResourceConfig={
                    "InstanceType": "ml.m5.large",
                    "InstanceCount": 1,
                    "VolumeSizeInGB": 5,
                },
                StoppingCondition={"MaxRuntimeInSeconds": 120},
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return
        except ClientError as exc:
            last_exc = exc
            code = exc.response["Error"]["Code"]
            message = str(exc).lower()
            if code == "ValidationException" and (
                "not authorized" in message
                or "assumerole" in message
                or "cannot be assumed" in message
                or "could not assume role" in message
            ):
                time.sleep(3)
                continue
            if code == "ResourceInUse":
                # a previous poll attempt already created it
                return
            raise
    raise AssertionError(f"could not create training job with fresh role in time: {last_exc}")


def _training_job_gone(exc) -> bool:
    """SageMaker reports a missing training job as ValidationException 'Requested resource not found'."""
    err = exc.response["Error"]
    return err["Code"] == "ResourceNotFound" or (
        err["Code"] == "ValidationException" and "not found" in err.get("Message", "").lower()
    )


def _stop_and_delete_training_job(sm, job_name: str) -> None:
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
