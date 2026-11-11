"""cfn-deploy-sagemaker-role-missing-s3-trust-negative."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-role-missing-s3-trust-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

# Region-pinned: each is AWS's own per-region ECR registry account for the built-in XGBoost
# algorithm image, not a value this check controls.
_XGBOOST_IMAGE_BY_REGION = {
    "us-east-1": "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.7-1",
    "us-west-2": "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-xgboost:1.7-1",
}

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  RoleWithS3Name:
    Type: String
  RoleWithoutS3Name:
    Type: String
  BucketName:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  RoleWithS3:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleWithS3Name
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: S3Access
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
  RoleWithoutS3:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleWithoutS3Name
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: NoS3Access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - cloudwatch:PutMetricData
                Resource: "*"
Outputs:
  RoleWithS3Arn:
    Value: !GetAtt RoleWithS3.Arn
  RoleWithoutS3Arn:
    Value: !GetAtt RoleWithoutS3.Arn
  BucketNameOut:
    Value: !Ref BucketName
"""


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CreateTrainingJob rejects synchronously, creating no job, when the role's permission
    policy grants no S3 access (the S3Prefix input needs s3:ListBucket), while an otherwise
    identical role with S3 access is accepted and completes with an output artifact."""
    image = _XGBOOST_IMAGE_BY_REGION.get(ctx.region)
    if image is None:
        raise AssertionError(
            f"no verified built-in XGBoost registry-path account ID recorded for region "
            f"{ctx.region!r} (only us-east-1/us-west-2 verified)."
        )

    role_with_name = ctx.unique_name("sim2real-xsvc-sm-role-with-")
    role_without_name = ctx.unique_name("sim2real-xsvc-sm-role-without-")
    bucket_name = ctx.unique_name("sim2real-xsvc-sm-bkt-")

    stack = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "RoleWithS3Name": role_with_name,
            "RoleWithoutS3Name": role_without_name,
            "BucketName": bucket_name,
        },
    )
    role_with_arn = stack["outputs"]["RoleWithS3Arn"]
    role_without_arn = stack["outputs"]["RoleWithoutS3Arn"]
    bucket = stack["outputs"]["BucketNameOut"]

    s3 = ctx.client("s3")
    # Registered after the stack's own delete, so it runs first: CloudFormation cannot delete a
    # non-empty bucket, and this check writes the input and the training output into it.
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="input/data.csv", Body=b"0,1\n1,0\n")

    sagemaker = ctx.client("sagemaker")

    def _job_kwargs(role_arn: str, output_prefix: str, job_name: str) -> dict[str, Any]:
        return dict(
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
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/{output_prefix}/"},
            ResourceConfig={
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeSizeInGB": 5,
            },
            StoppingCondition={"MaxRuntimeInSeconds": 600},
            Tags=_xsvc_tags_kv(),
        )

    # Positive control: role WITH S3 access is accepted and completes.
    positive_job = ctx.unique_name("sim2real-xsvc-sm-train-")
    sagemaker.create_training_job(
        **_job_kwargs(role_with_arn, "output-positive", positive_job)
    )

    def _best_effort_stop(job_name: str):
        def _stop():
            try:
                ctx.client("sagemaker").stop_training_job(TrainingJobName=job_name)
            except ClientError as exc:
                # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
                if exc.response["Error"]["Code"] != "ValidationException" or ctx.client("sagemaker").describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                    raise

        return _stop

    ctx.on_cleanup(lambda: _delete_trial_component(ctx, positive_job))
    ctx.on_cleanup(_best_effort_stop(positive_job))

    positive_described = _poll_until(
        lambda: sagemaker.describe_training_job(TrainingJobName=positive_job),
        lambda d: d["TrainingJobStatus"] in {"Completed", "Failed", "Stopped"},
        timeout_s=900.0,
        interval_s=10.0,
        description=f"positive-control training job {positive_job} to reach terminal status",
    )
    assert positive_described["TrainingJobStatus"] == "Completed", (
        f"expected Completed, got {positive_described['TrainingJobStatus']!r} "
        f"(FailureReason={positive_described.get('FailureReason')!r})"
    )
    # The artifact location is the job's OWN reported state, not a guessed key convention.
    artifact_uri = positive_described["ModelArtifacts"]["S3ModelArtifacts"]
    _, _, artifact_key = artifact_uri.partition(f"s3://{bucket}/")
    s3.head_object(Bucket=bucket, Key=artifact_key)

    # Negative: role WITHOUT any S3 grant is rejected synchronously, at CreateTrainingJob time.
    negative_job = ctx.unique_name("sim2real-xsvc-sm-train-")
    error = _client_error(
        lambda: sagemaker.create_training_job(
            **_job_kwargs(role_without_arn, "output-negative", negative_job)
        )
    )
    assert error.get("Code") == "ValidationException", error
    assert error.get("Message") == _no_s3_objects_message(
        ctx, f"s3://{bucket}/input/", bucket, role_without_arn, list_denied=True
    ), error

    # Effect absent: no job resource, and no output artifact, was ever created.
    describe_error = _client_error(
        lambda: sagemaker.describe_training_job(TrainingJobName=negative_job)
    )
    assert describe_error.get("Code") == "ValidationException", describe_error
    assert describe_error.get("Message") == "Requested resource not found.", describe_error
    listing = s3.list_objects_v2(
        Bucket=bucket, Prefix=f"output-negative/{negative_job}/"
    )
    assert listing.get("KeyCount", 0) == 0, (
        f"expected 0 objects under output-negative/{negative_job}/, "
        f"got {listing.get('KeyCount', 0)}: {listing.get('Contents')}"
    )


# ===== helpers =====

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict, or raise if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError("expected a ClientError, but the call succeeded")


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


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(s in msg for s in ("not found", "does not exist", "could not find"))
    )


def _delete_trial_component(ctx, job_name: str) -> None:
    # CreateTrainingJob auto-creates a "<job>-aws-training-job" trial component that
    # DeleteTrainingJob does not remove, so it is reclaimed here.
    try:
        ctx.client("sagemaker").delete_trial_component(TrialComponentName=f"{job_name}-aws-training-job")
    except ClientError as exc:
        if not _gone(exc):
            raise


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
        timeout_s=600,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        for entry in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"])


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


def _no_s3_objects_message(ctx, s3_uri: str, bucket: str, role_arn: str, *, list_denied: bool) -> str:
    """SageMaker's exact refusal when an input channel's S3 prefix lists no objects for the role."""
    message = (
        f'No S3 objects found under S3 URL "{s3_uri}" given in input data source. Please ensure '
        f"that the bucket exists in the selected region ({ctx.region}), that objects exist under "
        f'that S3 prefix, and that the role "{role_arn}" has "s3:ListBucket" permissions on '
        f'bucket "{bucket}".'
    )
    if list_denied:
        role_name = role_arn.rsplit("/", 1)[-1]
        message += (
            f" Error message from S3: User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/"
            f'SageMaker is not authorized to perform: s3:ListBucket on resource: "arn:aws:s3:::'
            f'{bucket}" because no identity-based policy allows the s3:ListBucket action'
        )
    return message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
