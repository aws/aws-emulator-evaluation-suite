"""e2e-experiment-trial-training-job-metrics-flow."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-experiment-trial-training-job-metrics-flow"
GROUP = "e2e"
SERVICES = ["sagemaker"]

_TAG = [{"Key": "sim2real-check", "Value": CHECK}]

# Well-known per-region ECR registry accounts that host the SageMaker built-in
# "linear-learner" algorithm image. Hardcoded rather than resolved via the
# `sagemaker` SDK's image_uris helper because that package is not guaranteed
# to be installed in the check's runtime.
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "plane:control")
def run(ctx) -> None:
    """A training job launched with ExperimentConfig auto-creates and associates a trial
    component under the trial, and that trial component's status ends up reflecting the
    training job's real final status -- not a value the client had to push itself."""
    sm = ctx.client("sagemaker")

    exp_name = ctx.unique_name("sim2real-exp-")
    trial_name = ctx.unique_name("sim2real-trial-")
    sm.create_experiment(ExperimentName=exp_name, Tags=_TAG)
    sm.create_trial(TrialName=trial_name, ExperimentName=exp_name, Tags=_TAG)
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=exp_name))
    ctx.on_cleanup(lambda: _cleanup_trial(sm, trial_name))

    role_arn = _create_sagemaker_role(ctx)
    bucket, data_key = _upload_training_data(ctx)
    image = _linear_learner_image(ctx.region)

    training_job_name = ctx.unique_name("sim2real-train-")
    _create_training_job_with_role_retry(
        sm,
        TrainingJobName=training_job_name,
        AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        InputDataConfig=[
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/{data_key}",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
                "ContentType": "text/csv",
                "CompressionType": "None",
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={
            "feature_dim": "3",
            "predictor_type": "regressor",
            "mini_batch_size": "20",
            "epochs": "3",
        },
        ExperimentConfig={
            "ExperimentName": exp_name,
            "TrialName": trial_name,
            "TrialComponentDisplayName": "sim2real-training-component",
        },
        Tags=_TAG,
    )
    ctx.on_cleanup(lambda: _best_effort_delete_training_job(sm, training_job_name))

    job = _poll_until(
        probe=lambda: sm.describe_training_job(TrainingJobName=training_job_name),
        predicate=lambda j: j["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    final_status = job["TrainingJobStatus"]
    assert final_status in ("Completed", "Failed"), f"expected a real terminal status, got {final_status!r}"

    training_job_arn = job["TrainingJobArn"]

    components = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    matches = [c for c in components if c.get("TrialComponentSource", {}).get("SourceArn") == training_job_arn]
    assert matches, f"no trial component auto-associated with training job {training_job_arn!r}: {components}"

    tc_name = matches[0]["TrialComponentName"]
    tc = sm.describe_trial_component(TrialComponentName=tc_name)
    assert tc["Status"]["PrimaryStatus"] == final_status, (
        f"trial component status {tc.get('Status')} did not mirror the training job's "
        f"real final status {final_status!r}"
    )


def _linear_learner_image(region):
    account = _LINEAR_LEARNER_REGISTRY.get(region)
    if not account:
        raise AssertionError(
            f"no known linear-learner built-in algorithm registry account for "
            f"region {region!r}; extend _LINEAR_LEARNER_REGISTRY to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _create_training_job_with_role_retry(sm, **kwargs):
    """A freshly created IAM role can take a few seconds to propagate before SageMaker
    can assume it; retry on that specific AccessDenied for a bounded window rather than
    sleeping a fixed duration before the first attempt."""
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ValidationException") and "assume" in str(exc).lower():
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAG
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _cleanup_trial(sm, trial_name):
    """Disassociate and delete the trial's components, then the trial; only not-found is accepted."""
    components = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    for c in components:
        name = c["TrialComponentName"]
        _ignore_not_found(lambda: sm.disassociate_trial_component(TrialComponentName=name, TrialName=trial_name))
        _ignore_not_found(lambda: sm.delete_trial_component(TrialComponentName=name))
    sm.delete_trial(TrialName=trial_name)


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _best_effort_delete_training_job(sm, name):
    """Stop the job if it still runs, wait for a terminal status, then delete it; failures raise."""
    terminal = ("Completed", "Failed", "Stopped")
    if sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] not in terminal:
        sm.stop_training_job(TrainingJobName=name)
        _poll_until(
            probe=lambda: sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"],
            predicate=lambda status: status in terminal,
            timeout_s=300.0,
            interval_s=10.0,
        )
    sm.delete_training_job(TrainingJobName=name)


def _upload_training_data(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint for the default region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAG})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)

    rng = random.Random(42)
    rows = []
    for _ in range(200):
        f1, f2, f3 = rng.random(), rng.random(), rng.random()
        label = f1 * 2.0 + f2 - f3 + rng.random() * 0.01
        rows.append(f"{label},{f1},{f2},{f3}")
    key = "train/data.csv"
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(rows).encode("utf-8"))
    return bucket, key


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    if predicate(last):
        return last
    raise AssertionError(f"condition never satisfied within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
