"""sagemaker-training-job-invalid-s3-uri-error-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-training-job-invalid-s3-uri-error-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateTrainingJob synchronously rejects an InputDataConfig S3Uri naming a
    bucket that does not exist with a ValidationException and creates no job, while
    an otherwise-identical job on a real bucket with data is accepted and completes."""
    image_uri = _xgboost_image_uri(ctx)
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="train/data.csv", Body=_training_csv())

    # A broad policy so the failure below is purely about bucket existence, not IAM.
    role_arn = _create_role(
        ctx,
        _s3_policy(list_bucket=["arn:aws:s3:::*"], get_object=["arn:aws:s3:::*/*"], put_object=["arn:aws:s3:::*/*"]),
    )

    nonexistent_bucket = ctx.unique_name("sim2real-sm-noexist-")
    bad_job_name = ctx.unique_name("sim2real-sm-baduri2-")
    bad_input_uri = f"s3://{nonexistent_bucket}/train/"
    bad_output_uri = f"s3://{bucket}/output-bad/"

    def _create_bad() -> None:
        ctx.client("sagemaker").create_training_job(
            **_training_job_params(bad_job_name, role_arn, image_uri, bad_input_uri, bad_output_uri)
        )

    # A just-created role is refused as unassumable until IAM propagates it; retry only that
    # exact refusal, bounded, so the bucket-existence refusal is what gets graded.
    unassumable = (
        "ValidationException",
        f"Could not assume role {role_arn}. Please ensure that the role exists and allows "
        f"principal 'sagemaker.amazonaws.com' to assume the role.",
    )
    deadline = time.monotonic() + 90.0
    code, message = _client_error(_create_bad)
    while (code, message) == unassumable and time.monotonic() < deadline:
        time.sleep(5)
        code, message = _client_error(_create_bad)
    expected_message = (
        f'No S3 objects found under S3 URL "{bad_input_uri}" given in input data source. Please '
        f"ensure that the bucket exists in the selected region ({ctx.region}), that objects exist "
        f'under that S3 prefix, and that the role "{role_arn}" has "s3:ListBucket" permissions on '
        f'bucket "{nonexistent_bucket}". Error message from S3: The specified bucket does not exist'
    )
    assert code == "ValidationException", (
        f"expected CreateTrainingJob to synchronously reject a non-existent input "
        f"bucket, got {(code, message)!r}"
    )
    assert message == expected_message, (
        f"expected CreateTrainingJob's rejection {expected_message!r}, got {message!r}"
    )
    not_found_code, not_found_message = _client_error(
        lambda: ctx.client("sagemaker").describe_training_job(TrainingJobName=bad_job_name)
    )
    assert not_found_code == "ValidationException", (
        "a training job rejected for a non-existent input bucket must never be "
        f"created, but describe_training_job returned {(not_found_code, not_found_message)!r}"
    )
    assert not_found_message == "Requested resource not found.", (
        f"unexpected describe_training_job not-found message {not_found_message!r}"
    )
    listed = s3.list_objects_v2(Bucket=bucket, Prefix=f"output-bad/{bad_job_name}/")
    assert listed.get("KeyCount", 0) == 0, "no model artifact should exist for a non-existent input bucket"


    good_job_name = ctx.unique_name("sim2real-sm-realuri-")
    good_input_uri = f"s3://{bucket}/train/"
    good_output_uri = f"s3://{bucket}/output-good/"
    _create_training_job_with_retry(
        ctx,
        **_training_job_params(good_job_name, role_arn, image_uri, good_input_uri, good_output_uri),
    )
    ctx.on_cleanup(lambda: _stop_training_job_ignore_errors(ctx, good_job_name))
    good_desc = _wait_for_training_job_terminal(ctx, good_job_name)
    assert good_desc["TrainingJobStatus"] == "Completed", (
        f"control job against a real bucket should complete, got {good_desc['TrainingJobStatus']}, "
        f"failure_reason={good_desc.get('FailureReason')}"
    )


# ===== helpers =====

# AWS's published, region-pinned ECR account IDs that host the built-in XGBoost
# algorithm image (https://docs.aws.amazon.com/sagemaker/latest/dg/xgboost.html) --
# a global constant, not a resource this check creates.
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


def _wait_for_training_job_terminal(ctx: Any, job_name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> dict:
    sm = ctx.client("sagemaker")
    terminal = {"Completed", "Failed", "Stopped"}
    deadline = time.monotonic() + timeout_s
    desc = sm.describe_training_job(TrainingJobName=job_name)
    while desc["TrainingJobStatus"] not in terminal and time.monotonic() < deadline:
        time.sleep(interval_s)
        desc = sm.describe_training_job(TrainingJobName=job_name)
    if desc["TrainingJobStatus"] not in terminal:
        raise AssertionError(f"training job {job_name} stuck in {desc['TrainingJobStatus']} after {timeout_s}s")
    return desc


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
