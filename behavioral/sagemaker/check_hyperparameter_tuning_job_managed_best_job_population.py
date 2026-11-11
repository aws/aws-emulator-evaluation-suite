"""hyperparameter-tuning-job-managed-best-job-population."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hyperparameter-tuning-job-managed-best-job-population"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateHyperParameterTuningJob runs its child training jobs server-side, evaluates each
    one's objective metric, and populates BestTrainingJob once DescribeHyperParameterTuningJob
    reports Completed."""
    image_uri = _xgboost_image_uri(ctx)
    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, bucket)
    train_uri = _upload_csv(ctx, bucket, "train/train.csv")
    validation_uri = _upload_csv(ctx, bucket, "validation/validation.csv")

    sm = ctx.client("sagemaker")
    # HyperParameterTuningJobName is capped at 32 chars; ctx.unique_name appends a 12-char
    # hex suffix, so the prefix must leave room for it.
    job_name = ctx.unique_name("sim2real-hpo-")
    ctx.on_cleanup(lambda: _best_effort_delete_tuning_job(ctx, job_name))

    _create_tuning_job_with_role_retry(
        sm,
        HyperParameterTuningJobName=job_name,
        HyperParameterTuningJobConfig={
            "Strategy": "Random",
            "HyperParameterTuningJobObjective": {
                "Type": "Minimize",
                "MetricName": "validation:logloss",
            },
            "ResourceLimits": {"MaxNumberOfTrainingJobs": 2, "MaxParallelTrainingJobs": 1},
            "ParameterRanges": {
                "ContinuousParameterRanges": [
                    {"Name": "eta", "MinValue": "0.1", "MaxValue": "0.5", "ScalingType": "Auto"}
                ]
            },
            "TrainingJobEarlyStoppingType": "Off",
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        TrainingJobDefinition={
            "StaticHyperParameters": {"objective": "binary:logistic", "num_round": "10"},
            "AlgorithmSpecification": {
                "TrainingImage": image_uri,
                "TrainingInputMode": "File",
            },
            "RoleArn": role_arn,
            "InputDataConfig": [
                {
                    "ChannelName": "train",
                    "ContentType": "text/csv",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": train_uri,
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                },
                {
                    "ChannelName": "validation",
                    "ContentType": "text/csv",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": validation_uri,
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                },
            ],
            "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output/"},
            "ResourceConfig": {
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeSizeInGB": 5,
            },
            "StoppingCondition": {"MaxRuntimeInSeconds": 900},
        },
    )

    initial = sm.describe_hyper_parameter_tuning_job(HyperParameterTuningJobName=job_name)
    assert initial["HyperParameterTuningJobStatus"] == "InProgress", (
        f"expected a freshly created tuning job to be InProgress, got "
        f"{initial['HyperParameterTuningJobStatus']}"
    )
    assert "BestTrainingJob" not in initial, (
        f"expected no BestTrainingJob before any child training job completes, got "
        f"{initial.get('BestTrainingJob')}"
    )

    final = _poll_until_terminal(
        lambda: sm.describe_hyper_parameter_tuning_job(HyperParameterTuningJobName=job_name),
        status_key="HyperParameterTuningJobStatus",
        terminal={"Completed", "Failed", "Stopped"},
        timeout_s=1800,
        interval_s=20,
    )

    assert final["HyperParameterTuningJobStatus"] == "Completed", (
        f"expected the tiny tuning job to complete, got "
        f"{final['HyperParameterTuningJobStatus']} ({final.get('FailureReason')})"
    )
    assert final["TrainingJobStatusCounters"]["Completed"] >= 1, (
        f"expected at least one completed child training job, got counters "
        f"{final['TrainingJobStatusCounters']}"
    )

    best = final.get("BestTrainingJob")
    assert best is not None, "service did not populate BestTrainingJob on a Completed tuning job"
    assert best["TrainingJobName"], f"BestTrainingJob has no TrainingJobName: {best}"
    assert best["TrainingJobStatus"] == "Completed", (
        f"expected BestTrainingJob to be Completed, got {best['TrainingJobStatus']}"
    )
    assert "FinalHyperParameterTuningJobObjectiveMetric" in best, (
        f"BestTrainingJob is missing its objective metric: {best}"
    )
    assert best["FinalHyperParameterTuningJobObjectiveMetric"]["MetricName"] == "validation:logloss", (
        f"expected the configured objective metric name, got "
        f"{best['FinalHyperParameterTuningJobObjectiveMetric']['MetricName']}"
    )

    # cross-check: the described training job the service picked really exists and agrees
    training_job = sm.describe_training_job(TrainingJobName=best["TrainingJobName"])
    assert training_job["TrainingJobStatus"] == "Completed", (
        f"BestTrainingJob {best['TrainingJobName']} is not independently Completed via "
        f"DescribeTrainingJob, got {training_job['TrainingJobStatus']}"
    )


# ===== helpers =====


#: SageMaker's built-in XGBoost image lives in a distinct ECR registry account per region. These are
#: the `sagemaker` PyPI SDK's OWN values (sagemaker 2.257.6,
#: ``sagemaker/image_uri_config/xgboost.json``, training+inference, versions 1.5-1 and 1.7-1 -- the
#: registry map is identical across those versions), so this is a transcription of the table
#: ``image_uris.retrieve`` reads, not a guess. It is inlined because pulling that SDK in just to
#: read a static JSON map costs torch + CUDA + mlflow and downgrades protobuf and
#: antlr4-python3-runtime in the runner.
_XGB_REGISTRY_ACCOUNTS = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-west-3": "659782779980",
    "sa-east-1": "737474898029",
}


def _xgboost_image_uri(ctx) -> str:
    region = ctx.region
    account = _XGB_REGISTRY_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no SageMaker built-in XGBoost ECR registry account mapped for region {region!r} "
            "- add it from the SDK's image_uri_config/xgboost.json to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sagemaker-sim2real-")
    # us-east-1 is the one region where CreateBucketConfiguration must be omitted entirely.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")

    def _empty() -> None:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])

    _ignore_gone(_empty)
    _ignore_gone(lambda: s3.delete_bucket(Bucket=name))


def _ignore_gone(fn) -> None:
    """Run a teardown call; return only when the resource is already gone, raise the rest."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket"):
            raise


def _upload_csv(ctx, bucket: str, key: str) -> str:
    s3 = ctx.client("s3")
    rows = [
        "0,1.0,2.0",
        "1,2.0,1.0",
        "0,1.5,2.5",
        "1,3.0,0.5",
        "0,0.5,3.0",
        "1,2.5,0.2",
        "0,0.8,2.8",
        "1,2.8,0.4",
    ]
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(rows).encode("utf-8"))
    return f"s3://{bucket}/{key}"


def _create_sagemaker_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sagemaker-sim2real-role-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_sagemaker_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(inline_policy)
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_sagemaker_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    _ignore_gone(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    _ignore_gone(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
        )
    )
    _ignore_gone(lambda: iam.delete_role(RoleName=role_name))


def _create_tuning_job_with_role_retry(sm, **kwargs):
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sm.create_hyper_parameter_tuning_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ValidationException") and "assume" in str(exc).lower():
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _poll_until_terminal(probe, status_key, terminal, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last[status_key] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"job never reached a terminal state within {timeout_s}s (last status: "
        f"{last[status_key] if last else 'unknown'})"
    )


def _best_effort_delete_tuning_job(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")

    def _status() -> str | None:
        try:
            return sm.describe_hyper_parameter_tuning_job(HyperParameterTuningJobName=job_name)[
                "HyperParameterTuningJobStatus"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return None
            raise

    status = _status()
    if status is None:
        return
    if status == "InProgress":
        try:
            sm.stop_hyper_parameter_tuning_job(HyperParameterTuningJobName=job_name)
        except ClientError as exc:
            # The job reached a terminal state between the describe and the stop.
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
    # A tuning job is deletable only once it has left InProgress/Stopping.
    deadline = time.monotonic() + 600
    while status in ("InProgress", "Stopping"):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"tuning job {job_name} still {status} 600s after stopping it")
        time.sleep(2)
        status = _status()
    if status is not None:
        _ignore_gone(lambda: sm.delete_hyper_parameter_tuning_job(HyperParameterTuningJobName=job_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
