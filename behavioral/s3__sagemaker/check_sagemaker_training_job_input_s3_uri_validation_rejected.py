"""sagemaker-training-job-input-s3-uri-validation-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-training-job-input-s3-uri-validation-rejected"
GROUP = "data-format"
SERVICES = ["s3", "sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob rejects a channel S3Uri that breaks the s3:// / https://
    URI syntax with a synchronous ValidationException and creates no job, while a
    well-formed S3Uri for the same role and bucket is accepted."""
    image_uri = _xgboost_image_uri(ctx)

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="train/data.csv", Body=_training_csv())

    role_arn = _create_role(
        ctx,
        _s3_policy(
            list_bucket=[f"arn:aws:s3:::{bucket}"],
            get_object=[f"arn:aws:s3:::{bucket}/train/*"],
            put_object=[f"arn:aws:s3:::{bucket}/output/*"],
        ),
    )
    output_uri = f"s3://{bucket}/output/"

    bad_job_name = ctx.unique_name("sim2real-sm-baduri-")
    bad_params = _training_job_params(bad_job_name, role_arn, image_uri, "not-a-valid-s3-uri", output_uri)

    def _create_bad() -> None:
        ctx.client("sagemaker").create_training_job(**bad_params)

    error = _client_error(_create_bad)
    assert error == (
        "ValidationException",
        "1 validation error detected: Value 'not-a-valid-s3-uri' at "
        "'inputDataConfig.1.member.dataSource.s3DataSource.s3Uri' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: (https|s3)://([^/]+)/?(.*)",
    ), f"expected the S3Uri pattern refusal, got {error!r}"

    not_found = _client_error(
        lambda: ctx.client("sagemaker").describe_training_job(TrainingJobName=bad_job_name)
    )
    assert not_found == ("ValidationException", "Requested resource not found."), (
        "rejected CreateTrainingJob must never create a job, so describe_training_job "
        f"must fail with not-found, got {not_found!r}"
    )

    good_job_name = ctx.unique_name("sim2real-sm-gooduri-")
    good_params = _training_job_params(good_job_name, role_arn, image_uri, f"s3://{bucket}/train/", output_uri)
    _create_training_job_with_retry(ctx, **good_params)
    ctx.on_cleanup(lambda: _stop_training_job_ignore_errors(ctx, good_job_name))
    desc = ctx.client("sagemaker").describe_training_job(TrainingJobName=good_job_name)
    assert desc["TrainingJobStatus"] in {"InProgress", "Downloading", "Starting", "Completed", "Stopping", "Stopped"}, (
        f"expected a well-formed S3Uri to be accepted and the job to progress, "
        f"got TrainingJobStatus={desc['TrainingJobStatus']!r}, FailureReason={desc.get('FailureReason')!r}"
    )
    ctx.client("sagemaker").stop_training_job(TrainingJobName=good_job_name)


# ===== helpers =====

# AWS's own fixed per-region ECR registry accounts for the built-in XGBoost image; looked up
# by ctx.region, never a region override.
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    return role_arn


def _training_job_params(job_name, role_arn, image_uri, input_s3_uri, output_s3_uri, max_runtime_s=900):
    return dict(
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        InputDataConfig=[
            {
                "ChannelName": "train",
                "ContentType": "text/csv",
                "CompressionType": "None",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": input_s3_uri,
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        OutputDataConfig={"S3OutputPath": output_s3_uri},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": max_runtime_s},
        HyperParameters={"objective": "binary:logistic", "num_round": "3", "max_depth": "2"},
    )


def _create_training_job_with_retry(ctx: Any, **kwargs: Any) -> dict:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + 45.0
    while True:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ValidationException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _stop_training_job_ignore_errors(ctx: Any, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
            raise


def _client_error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn raises; raises AssertionError when fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call succeeded, but AWS refuses it")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
