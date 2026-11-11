"""sagemaker-hyperparameter-tuning-job-s3-artifacts-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-hyperparameter-tuning-job-s3-artifacts-positive"
GROUP = "artifact-output"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A hyperparameter tuning job's best training job writes its model artifact to
    the configured S3 output path, exactly like a standalone training job would."""
    image_uri = _xgboost_image_uri(ctx)

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="train/data.csv", Body=_training_csv())
    s3.put_object(Bucket=bucket, Key="validation/data.csv", Body=_training_csv())

    role_arn = _create_role(
        ctx,
        _s3_policy(
            list_bucket=[f"arn:aws:s3:::{bucket}"],
            get_object=[f"arn:aws:s3:::{bucket}/train/*", f"arn:aws:s3:::{bucket}/validation/*"],
            put_object=[f"arn:aws:s3:::{bucket}/tuning-output/*"],
        ),
    )

    input_uri = f"s3://{bucket}/train/"
    validation_uri = f"s3://{bucket}/validation/"
    output_uri = f"s3://{bucket}/tuning-output/"
    tuning_job_name = ctx.unique_name("sim2real-sm-hpo-")
    sm = ctx.client("sagemaker")
    tuning_params = dict(
        HyperParameterTuningJobName=tuning_job_name,
        HyperParameterTuningJobConfig={
            "Strategy": "Random",
            "HyperParameterTuningJobObjective": {"Type": "Minimize", "MetricName": "validation:error"},
            "ResourceLimits": {"MaxNumberOfTrainingJobs": 1, "MaxParallelTrainingJobs": 1},
            "ParameterRanges": {
                "ContinuousParameterRanges": [{"Name": "eta", "MinValue": "0.1", "MaxValue": "0.5"}]
            },
        },
        TrainingJobDefinition={
            "StaticHyperParameters": {"objective": "binary:logistic", "num_round": "3", "max_depth": "2"},
            "AlgorithmSpecification": {
                "TrainingImage": image_uri,
                "TrainingInputMode": "File",
                "MetricDefinitions": [
                    {"Name": "validation:error", "Regex": r"validation-error:([0-9\.]+)"}
                ],
            },
            "RoleArn": role_arn,
            "InputDataConfig": [
                {
                    "ChannelName": "train",
                    "ContentType": "text/csv",
                    "CompressionType": "None",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": input_uri,
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                },
                {
                    "ChannelName": "validation",
                    "ContentType": "text/csv",
                    "CompressionType": "None",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": validation_uri,
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                },
            ],

            "OutputDataConfig": {"S3OutputPath": output_uri},
            "ResourceConfig": {"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            "StoppingCondition": {"MaxRuntimeInSeconds": 900},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    _create_tuning_job_with_retry(ctx, **tuning_params)
    ctx.on_cleanup(lambda: _stop_tuning_job_ignore_errors(ctx, tuning_job_name))


    tuning_desc = _wait_for_tuning_job_terminal(ctx, tuning_job_name)
    assert tuning_desc["HyperParameterTuningJobStatus"] == "Completed", (
        f"tuning job did not complete "
        f"(status={tuning_desc['HyperParameterTuningJobStatus']}, "
        f"reason={tuning_desc.get('FailureReason')})"
    )

    best_job_name = tuning_desc["BestTrainingJob"]["TrainingJobName"]
    best_desc = sm.describe_training_job(TrainingJobName=best_job_name)
    assert best_desc["TrainingJobStatus"] == "Completed", (
        f"best training job {best_job_name} not completed "
        f"(status={best_desc['TrainingJobStatus']}, reason={best_desc.get('FailureReason')})"
    )

    artifact_uri = best_desc["ModelArtifacts"]["S3ModelArtifacts"]
    expected_artifact_uri = f"{output_uri}{best_job_name}/output/model.tar.gz"
    assert artifact_uri == expected_artifact_uri, (
        f"expected the best training job's model artifact at {expected_artifact_uri}, "
        f"got {artifact_uri}"
    )
    key = artifact_uri[len(f"s3://{bucket}/") :]
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] > 0, f"model artifact at s3://{bucket}/{key} is empty"


# ===== helpers =====

# AWS's documented built-in XGBoost algorithm container registry account, one per region
# (https://docs.aws.amazon.com/sagemaker/latest/dg/xgboost.html) -- these accounts are pinned by
# AWS, not guessed, and there is no account-agnostic way to resolve one.
_XGBOOST_REGISTRY_ACCOUNTS = {
    "af-south-1": "510948584623", "ap-east-1": "651117190479",
    "ap-northeast-1": "354813040037", "ap-northeast-2": "366743142698",
    "ap-northeast-3": "867004704886", "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041", "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497", "eu-central-1": "492215442770",
    "eu-north-1": "662702820516", "eu-south-1": "978288397137",
    "eu-west-1": "141502667606", "eu-west-2": "764974769150",
    "eu-west-3": "659782779980", "me-south-1": "801668240914",
    "sa-east-1": "737474898029", "us-east-1": "683313688378",
    "us-east-2": "257758044811", "us-west-1": "746614075791",
    "us-west-2": "246618743249",
}


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "RepositoryNotFoundException") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
    )


def _xgboost_image_uri(ctx: Any) -> str:
    try:
        from sagemaker import image_uris
        return image_uris.retrieve(framework="xgboost", region=ctx.region, version="1.5-1")
    except Exception:
        pass
    account = _XGBOOST_REGISTRY_ACCOUNTS.get(ctx.region)
    if not account:
        raise AssertionError(
            f"no known built-in XGBoost ECR registry account for region {ctx.region}"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.5-1"


def _training_csv(n_rows: int = 40) -> bytes:
    lines = []
    for i in range(n_rows):
        label = i % 2
        f1 = float(i) * 0.37 + label * 5.0
        f2 = float(i) * 0.11 - label * 2.0
        f3 = float(i % 5)
        lines.append(f"{label},{f1:.3f},{f2:.3f},{f3:.3f}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=name)


def _s3_policy(list_bucket=None, get_object=None, put_object=None) -> dict:
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:CreateLogGroup",
                "logs:DescribeLogStreams",
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
            ],
            "Resource": "*",
        }
    ]
    if list_bucket:
        statements.append({"Effect": "Allow", "Action": "s3:ListBucket", "Resource": list_bucket})
    if get_object:
        statements.append({"Effect": "Allow", "Action": "s3:GetObject", "Resource": get_object})
    if put_object:
        statements.append({"Effect": "Allow", "Action": "s3:PutObject", "Resource": put_object})
    return {"Version": "2012-10-17", "Statement": statements}


def _create_role(ctx: Any, inline_policy: dict, trust_service: str = "sagemaker.amazonaws.com") -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    return role_arn


def _wait_for_tuning_job_terminal(ctx: Any, tuning_job_name: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> dict:
    sm = ctx.client("sagemaker")
    terminal = {"Completed", "Failed", "Stopped"}
    deadline = time.monotonic() + timeout_s
    desc = sm.describe_hyper_parameter_tuning_job(HyperParameterTuningJobName=tuning_job_name)
    while desc["HyperParameterTuningJobStatus"] not in terminal and time.monotonic() < deadline:
        time.sleep(interval_s)
        desc = sm.describe_hyper_parameter_tuning_job(HyperParameterTuningJobName=tuning_job_name)
    if desc["HyperParameterTuningJobStatus"] not in terminal:
        raise AssertionError(
            f"tuning job {tuning_job_name} stuck in {desc['HyperParameterTuningJobStatus']} after {timeout_s}s"
        )
    return desc


def _stop_tuning_job_ignore_errors(ctx: Any, tuning_job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.stop_hyper_parameter_tuning_job(HyperParameterTuningJobName=tuning_job_name)
    except ClientError as exc:
        if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_hyper_parameter_tuning_job(HyperParameterTuningJobName=tuning_job_name)["HyperParameterTuningJobStatus"] == "InProgress"):
            raise


def _create_tuning_job_with_retry(ctx: Any, **kwargs: Any) -> dict:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + 45.0
    while True:
        try:
            return sm.create_hyper_parameter_tuning_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ValidationException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
