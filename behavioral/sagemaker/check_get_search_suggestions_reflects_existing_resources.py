"""get-search-suggestions-reflects-existing-resources."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-search-suggestions-reflects-existing-resources"
GROUP = "data-plane"
SERVICES = ["sagemaker"]

_LINEAR_LEARNER_REGISTRY = {
    "us-east-1": "382416733822",
    "us-west-2": "174872318107",
}


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSearchSuggestions completes a truncated hint to the custom hyperparameter key of a
    TrainingJob this check launched, so the suggestions reflect real account resources."""
    sm = ctx.client("sagemaker")

    role_arn = _create_sagemaker_role(ctx)
    hp_key = ctx.unique_name("sim2realhp").replace("-", "")

    # CreateTrainingJob rejects an empty ECR repo and a public.ecr.aws image, so use the
    # AWS-owned linear-learner image:
    # https://docs.aws.amazon.com/sagemaker/latest/dg/ecr-us-west-2.html
    training_image = f"{_LINEAR_LEARNER_REGISTRY[ctx.region]}.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1"

    job_name = ctx.unique_name("sim2real-search-train-")
    _create_training_job_with_retry(
        ctx,
        sm,
        TrainingJobName=job_name,
        AlgorithmSpecification={
            "TrainingImage": training_image,
            "TrainingInputMode": "File",
        },
        RoleArn=role_arn,
        OutputDataConfig={"S3OutputPath": f"s3://sim2real-nonexistent-bucket-{job_name}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 120},
        HyperParameters={hp_key: "sim2real-value"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_training_job(sm, job_name))
    # CreateTrainingJob auto-creates a default trial component ("<job>-aws-training-job")
    # to track it even outside an experiment; it outlives DeleteTrainingJob and must be
    # deleted on its own.
    ctx.on_cleanup(lambda: _best_effort_delete_trial_component(sm, f"{job_name}-aws-training-job"))

    # AWS returns the namespace prefix lowercase ("hyperparameters."), not "HyperParameters.".
    expected_property = f"hyperparameters.{hp_key}"
    hint = f"hyperparameters.{hp_key[:-4]}"

    found = _poll_until(
        ctx,
        probe=lambda: sm.get_search_suggestions(
            Resource="TrainingJob",
            SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": hint}},
        ).get("PropertyNameSuggestions", []),
        predicate=lambda suggestions: any(s.get("PropertyName") == expected_property for s in suggestions),
        timeout_s=90.0,
        interval_s=2.0,
    )
    assert any(s.get("PropertyName") == expected_property for s in found), (
        f"expected suggestion {expected_property!r} derived from the real training job, got {found!r}"
    )


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        from botocore.exceptions import ClientError

        for delete in (
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                delete()
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup)
    # IAM trust/attachment propagation is eventually consistent: CreateTrainingJob is retried
    # on the transient AccessDenied/ValidationException until the role is usable.
    return role_arn


def _deadline(ctx, timeout_s: float) -> float:
    """Monotonic deadline ``timeout_s`` ahead, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


def _create_training_job_with_retry(ctx, sm, timeout_s=60.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = _deadline(ctx, timeout_s)
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            last_err = err
            if code in ("AccessDeniedException", "ValidationException"):
                time.sleep(2)
                continue
            raise
    raise last_err


def _best_effort_delete_training_job(sm, name):
    from botocore.exceptions import ClientError

    try:
        sm.stop_training_job(TrainingJobName=name)
    except ClientError as err:
        # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
        if err.response["Error"]["Code"] == "ResourceNotFound":
            return
        if err.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] == "InProgress":
            raise
    # DeleteTrainingJob is refused with ResourceInUse while the job is still stopping.
    deadline = time.monotonic() + 180.0
    while True:
        try:
            sm.delete_training_job(TrainingJobName=name)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _best_effort_delete_trial_component(sm, name):
    from botocore.exceptions import ClientError

    try:
        sm.delete_trial_component(TrialComponentName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(ctx, probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = _deadline(ctx, timeout_s)
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

