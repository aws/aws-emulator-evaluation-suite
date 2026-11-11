"""training-job-hyperparameter-numeric-precision-preserved."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "training-job-hyperparameter-numeric-precision-preserved"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A high-precision floating point hyperparameter string survives CreateTrainingJob
    and is returned character-for-character identical on DescribeTrainingJob, with no
    rounding, truncation, or re-formatting of the numeric text."""
    role_arn = _create_sagemaker_role(ctx)
    sm = ctx.client("sagemaker")
    job_name = ctx.unique_name("sim2real-hpprec-")

    precise_learning_rate = "0.0000123456789012345678901234"
    precise_reg = "1.00000000000000000000001"

    _create_training_job_with_role_retry(
        sm,
        job_name=job_name,
        role_arn=role_arn,
        hyperparameters={
            "learning_rate": precise_learning_rate,
            "l1": precise_reg,
        },
        output_path=f"s3://sim2real-behav-{uuid.uuid4().hex}/out",
        region=ctx.region,
    )

    def _stop_quiet():
        """Stop the job unless it already ended or is stopping; ResourceNotFound passes."""
        try:
            status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
            if status not in ("Completed", "Failed", "Stopped", "Stopping"):
                sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise

    ctx.on_cleanup(_stop_quiet)

    desc = sm.describe_training_job(TrainingJobName=job_name)
    assert desc["HyperParameters"]["learning_rate"] == precise_learning_rate, (
        f"learning_rate precision not preserved: {desc['HyperParameters'].get('learning_rate')!r} "
        f"!= {precise_learning_rate!r}"
    )
    assert desc["HyperParameters"]["l1"] == precise_reg
    # Round-trip through JSON too, to be sure describe_training_job isn't handing back
    # a numeric type that Python's json module would have rounded on the way out.
    round_tripped = json.loads(json.dumps(desc["HyperParameters"]))
    assert round_tripped["learning_rate"] == precise_learning_rate

    # Immediately stop the job to avoid burning real training compute time/cost;
    # the hyperparameters are already durably persisted by CreateTrainingJob.
    sm.stop_training_job(TrainingJobName=job_name)


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-smrole-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _create_training_job_with_role_retry(
    sm, *, job_name, role_arn, hyperparameters, output_path, region
):
    """IAM role trust/attachment propagation is eventually consistent; the only
    observable condition is SageMaker's own acceptance of the role, so poll
    CreateTrainingJob itself (bounded, with a stated reason) rather than sleeping a
    fixed duration before the first attempt."""
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            sm.create_training_job(
                TrainingJobName=job_name,
                AlgorithmSpecification={
                    # CreateTrainingJob synchronously checks that the role can pull the
                    # image, so a placeholder ECR repo is rejected; use AWS's own
                    # built-in linear-learner image for this region (registry id
                    # differs per region -- this is the us-west-2 one).
                    "TrainingImage": f"174872318107.dkr.ecr.{region}.amazonaws.com/linear-learner:1",
                    "TrainingInputMode": "File",
                },
                RoleArn=role_arn,
                HyperParameters=hyperparameters,
                OutputDataConfig={"S3OutputPath": output_path},
                ResourceConfig={
                    "InstanceType": "ml.m5.large",
                    "InstanceCount": 1,
                    "VolumeSizeInGB": 10,
                },
                StoppingCondition={"MaxRuntimeInSeconds": 600},
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
                # a previous attempt in this loop already created it despite raising
                return
            raise
    raise AssertionError(f"could not create training job with fresh role in time: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
