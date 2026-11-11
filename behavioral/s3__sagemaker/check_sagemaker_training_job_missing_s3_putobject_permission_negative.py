"""sagemaker-training-job-missing-s3-putobject-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-training-job-missing-s3-putobject-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A training job whose role lacks s3:PutObject on the output bucket trains, then
    fails uploading model.tar.gz and writes no artifact, while an otherwise-identical
    job with s3:PutObject completes and writes it."""
    image_uri = _xgboost_image_uri(ctx)
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="train/data.csv", Body=_training_csv())
    input_uri = f"s3://{bucket}/train/"

    # Negative: role can read the input but cannot write the output prefix.
    no_put_role = _create_role(
        ctx,
        _s3_policy(
            list_bucket=[f"arn:aws:s3:::{bucket}"],
            get_object=[f"arn:aws:s3:::{bucket}/train/*"],
        ),
    )
    bad_job_name = ctx.unique_name("sim2real-sm-noput-")
    bad_output_uri = f"s3://{bucket}/output-noput/"
    _create_training_job_with_retry(
        ctx,
        **_training_job_params(bad_job_name, no_put_role, image_uri, input_uri, bad_output_uri),
    )
    ctx.on_cleanup(lambda: _stop_training_job_ignore_errors(ctx, bad_job_name))

    # Positive control: identical setup, but with s3:PutObject granted. Submitted
    # right after the negative job (before waiting on it) so both jobs run
    # concurrently and the check fits in the harness timeout.
    good_role = _create_role(
        ctx,
        _s3_policy(
            list_bucket=[f"arn:aws:s3:::{bucket}"],
            get_object=[f"arn:aws:s3:::{bucket}/train/*"],
            put_object=[f"arn:aws:s3:::{bucket}/output-ok/*"],
        ),
    )
    good_job_name = ctx.unique_name("sim2real-sm-putok-")
    good_output_uri = f"s3://{bucket}/output-ok/"
    _create_training_job_with_retry(
        ctx,
        **_training_job_params(good_job_name, good_role, image_uri, input_uri, good_output_uri),
    )
    ctx.on_cleanup(lambda: _stop_training_job_ignore_errors(ctx, good_job_name))

    bad_desc, good_desc = _wait_for_training_jobs_terminal(ctx, [bad_job_name, good_job_name])
    assert bad_desc["TrainingJobStatus"] == "Failed", (
        f"expected Failed without s3:PutObject, got {bad_desc['TrainingJobStatus']}, "
        f"failure_reason={bad_desc.get('FailureReason')}"
    )
    bad_reason = bad_desc.get("FailureReason", "")
    assert "not authorized" in bad_reason.lower() or "access denied" in bad_reason.lower(), (
        f"expected an access-denied failure reason attributing the failure to the missing "
        f"s3:PutObject grant, got: {bad_reason!r}"
    )
    listed = s3.list_objects_v2(Bucket=bucket, Prefix=f"output-noput/{bad_job_name}/")
    assert listed.get("KeyCount", 0) == 0, "no model artifact should exist without output write access"

    assert good_desc["TrainingJobStatus"] == "Completed", (
        f"control job with s3:PutObject should complete, got {good_desc['TrainingJobStatus']}, "
        f"failure_reason={good_desc.get('FailureReason')}"
    )
    good_listed = s3.list_objects_v2(Bucket=bucket, Prefix=f"output-ok/{good_job_name}/")
    assert any(o["Key"].endswith("model.tar.gz") for o in good_listed.get("Contents", [])), (
        "control job with s3:PutObject granted should have written a model artifact, "
        f"but none was found under output-ok/{good_job_name}/"
    )


# ===== helpers =====

# AWS-owned ECR registry accounts hosting the built-in XGBoost algorithm image, one
# per region; fixed and publicly documented, not an account-specific value.
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
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


def _wait_for_training_jobs_terminal(
    ctx: Any, job_names: list[str], timeout_s: float = 900.0, interval_s: float = 15.0
) -> list[dict]:
    """Poll multiple training jobs concurrently (one shared deadline) so waiting on
    N jobs costs max(job durations) instead of sum(job durations)."""
    sm = ctx.client("sagemaker")
    terminal = {"Completed", "Failed", "Stopped"}
    deadline = time.monotonic() + timeout_s
    descs = {name: sm.describe_training_job(TrainingJobName=name) for name in job_names}
    while time.monotonic() < deadline and any(
        descs[name]["TrainingJobStatus"] not in terminal for name in job_names
    ):
        time.sleep(interval_s)
        for name in job_names:
            if descs[name]["TrainingJobStatus"] not in terminal:
                descs[name] = sm.describe_training_job(TrainingJobName=name)
    for name in job_names:
        if descs[name]["TrainingJobStatus"] not in terminal:
            raise AssertionError(
                f"training job {name} stuck in {descs[name]['TrainingJobStatus']} after {timeout_s}s"
            )
    return [descs[name] for name in job_names]


def _stop_training_job_ignore_errors(ctx: Any, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
