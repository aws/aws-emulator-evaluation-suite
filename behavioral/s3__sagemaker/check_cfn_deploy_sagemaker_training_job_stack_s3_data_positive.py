"""cfn-deploy-sagemaker-training-job-stack-s3-data-positive."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-training-job-stack-s3-data-positive"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

# Best-known public registry paths for the SageMaker built-in XGBoost algorithm container
# (see the SageMaker Python SDK's image_uris config / AWS's "Docker Registry Paths and Example
# Code" page). Deliberately limited to the two regions the author has high confidence in; any
# other region honestly skips rather than risk a false FAIL from a wrong account ID.
_XGBOOST_IMAGE_BY_REGION = {
    "us-east-1": "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.7-1",
    "us-west-2": "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-xgboost:1.7-1",
}

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  RoleName:
    Type: String
  BucketName:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  TrainingRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: S3TrainingDataAccess
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
                  - s3:PutObject
                Resource:
                  - !Sub "arn:aws:s3:::${BucketName}"
                  - !Sub "arn:aws:s3:::${BucketName}/*"
Outputs:
  RoleArn:
    Value: !GetAtt TrainingRole.Arn
  BucketNameOut:
    Value: !Ref BucketName
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN-deployed role+bucket stack, wired to a real SageMaker training job's S3 input and
    output paths, produces a job that reaches Completed and leaves the expected model artifact
    at the exact S3 output location SageMaker derives from OutputDataConfig.S3OutputPath."""
    image = _XGBOOST_IMAGE_BY_REGION.get(ctx.region)
    if image is None:
        raise AssertionError(
            f"no verified built-in XGBoost registry-path account ID recorded for region "
            f"{ctx.region!r} (only us-east-1/us-west-2 verified); would need that region's "
            "account ID from the SageMaker built-in algorithm Docker registry table to run."
        )

    role_name = ctx.unique_name("sim2real-xsvc-sm-role-")
    bucket_name = ctx.unique_name("sim2real-xsvc-sm-bkt-")

    stack = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"RoleName": role_name, "BucketName": bucket_name},
    )
    role_arn = stack["outputs"]["RoleArn"]
    bucket = stack["outputs"]["BucketNameOut"]

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="input/data.csv", Body=b"0,1\n1,0\n0,1\n")
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    sagemaker = ctx.client("sagemaker")
    job_name = ctx.unique_name("sim2real-xsvc-sm-train-")
    sagemaker.create_training_job(
        TrainingJobName=job_name,
        RoleArn=role_arn,
        AlgorithmSpecification={
            "TrainingImage": image,
            "TrainingInputMode": "File",
            "ContainerEntrypoint": ["/bin/bash", "-c"],
            "ContainerArguments": [
                "mkdir -p /opt/ml/model && echo trained-artifact > /opt/ml/model/model.txt"
            ],
        },
        InputDataConfig=[
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/input/",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
                "ContentType": "text/csv",
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={
            "InstanceType": "ml.m5.large",
            "InstanceCount": 1,
            "VolumeSizeInGB": 5,
        },
        StoppingCondition={"MaxRuntimeInSeconds": 600},
        Tags=_xsvc_tags_kv(),
    )

    def _best_effort_stop():
        try:
            ctx.client("sagemaker").stop_training_job(TrainingJobName=job_name)
        except ClientError as exc:
            # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
            if exc.response["Error"]["Code"] != "ValidationException" or ctx.client("sagemaker").describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise

    ctx.on_cleanup(_best_effort_stop)

    described = _poll_until(
        lambda: sagemaker.describe_training_job(TrainingJobName=job_name),
        lambda d: d["TrainingJobStatus"] in {"Completed", "Failed", "Stopped"},
        timeout_s=900.0,
        interval_s=10.0,
        description=f"training job {job_name} to reach a terminal status",
    )
    assert described["TrainingJobStatus"] == "Completed", described.get("FailureReason")

    expected_artifact = f"s3://{bucket}/output/{job_name}/output/model.tar.gz"
    actual_artifact = described["ModelArtifacts"]["S3ModelArtifacts"]
    assert actual_artifact == expected_artifact, (
        f"expected model artifact at {expected_artifact!r}, SageMaker reported {actual_artifact!r}"
    )
    key = f"output/{job_name}/output/model.tar.gz"
    s3.head_object(Bucket=bucket, Key=key)  # raises if the artifact truly isn't there


# ===== helpers =====

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    to_delete = []
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            to_delete.append({"Key": obj["Key"]})
    for i in range(0, len(to_delete), 1000):
        chunk = to_delete[i : i + 1000]
        if chunk:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": chunk})


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(s in msg for s in ("not found", "does not exist", "could not find"))
    )


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not _gone(exc):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
