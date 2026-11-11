"""cfn-deploy-sagemaker-missing-s3-bucket-policy-negative."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-missing-s3-bucket-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RoleNoS3Name:
    Type: String
  RoleWithS3Name:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
  BaseExecPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - logs:CreateLogGroup
              - logs:CreateLogStream
              - logs:PutLogEvents
              - ecr:GetAuthorizationToken
              - ecr:BatchCheckLayerAvailability
              - ecr:GetDownloadUrlForLayer
              - ecr:BatchGetImage
            Resource: '*'
  RoleNoS3:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleNoS3Name
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - !Ref BaseExecPolicy
  RoleWithS3:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleWithS3Name
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - !Ref BaseExecPolicy
      Policies:
        - PolicyName: s3-scoped-access
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt DataBucket.Arn
                  - !Sub '${DataBucket.Arn}/*'
Outputs:
  BucketName:
    Value: !Ref DataBucket
  RoleNoS3Arn:
    Value: !GetAtt RoleNoS3.Arn
  RoleWithS3Arn:
    Value: !GetAtt RoleWithS3.Arn
"""

# Real, AWS-published per-region ECR account IDs that host the linear-learner built-in
# algorithm image; region-pinned because the image URI itself is region-scoped.
_LINEAR_LEARNER_ACCOUNT_BY_REGION = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "469771592824",
    "eu-central-1": "664544806723",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "sa-east-1": "855470959533",
}


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
    """CreateTrainingJob with a role lacking S3 access to the input bucket is rejected with
    ValidationException naming s3:ListBucket and creates no job, while an otherwise-identical
    role with bucket access trains to completion and writes a model artifact."""
    image = _linear_learner_image(ctx.region)
    result = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "RoleNoS3Name": _xname(ctx, "norole"),
            "RoleWithS3Name": _xname(ctx, "yesrole"),
        },
        timeout_s=180.0,
    )
    bucket = result["outputs"]["BucketName"]
    role_no_s3 = result["outputs"]["RoleNoS3Arn"]
    role_with_s3 = result["outputs"]["RoleWithS3Arn"]

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_tiny_binary_csv())
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    sm = ctx.client("sagemaker")
    job_no_s3 = _xname(ctx, "denyjob")
    job_with_s3 = _xname(ctx, "allowjob")

    def _launch(job_name: str, role_arn: str) -> None:
        sm.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={
                "TrainingImage": image,
                "TrainingInputMode": "File",
            },
            RoleArn=role_arn,
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{bucket}/train/",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                    "ContentType": "text/csv",
                }
            ],
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/{job_name}/"},
            ResourceConfig={
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeSizeInGB": 5,
            },
            StoppingCondition={"MaxRuntimeInSeconds": 900},
            HyperParameters={
                "predictor_type": "binary_classifier",
                "feature_dim": "2",
                "mini_batch_size": "8",
            },
            Tags=_xsvc_tags_kv(),
        )
        ctx.on_cleanup(lambda: _safe_stop_training_job(ctx, job_name))
        ctx.on_cleanup(lambda: _safe_delete_trial_component(ctx, job_name))

    # Negative: SageMaker validates S3 accessibility of the input channel synchronously,
    # inside CreateTrainingJob itself -- a role with no s3:ListBucket on the bucket is
    # rejected on the spot, before any job resource exists.
    try:
        _launch(job_no_s3, role_no_s3)
    except ClientError as exc:
        error = exc.response["Error"]
    else:
        raise AssertionError(
            f"expected CreateTrainingJob for {job_no_s3} to be rejected synchronously "
            "(role has no s3:ListBucket on the input bucket), but it was accepted"
        )
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == _no_s3_objects_message(
        ctx, f"s3://{bucket}/train/", bucket, role_no_s3, list_denied=True
    ), error["Message"]

    # Effect absent: the job was never created at all, at an independent read.
    try:
        sm.describe_training_job(TrainingJobName=job_no_s3)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ValidationException", exc.response[
            "Error"
        ]
        assert exc.response["Error"]["Message"] == "Requested resource not found.", (
            exc.response["Error"]
        )
    else:
        raise AssertionError(
            f"expected training job {job_no_s3} to not exist, but it does"
        )

    _launch(job_with_s3, role_with_s3)

    # Positive control: identical setup, but the role has S3 access -> job completes.
    status_with_s3 = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_with_s3)[
            "TrainingJobStatus"
        ],
        lambda s: s in {"Completed", "Failed", "Stopped"},
        timeout_s=900.0,
        interval_s=15.0,
        description=f"training job {job_with_s3} terminal",
    )
    desc_with_s3 = sm.describe_training_job(TrainingJobName=job_with_s3)
    assert status_with_s3 == "Completed", desc_with_s3.get("FailureReason")

    # Effect present: the job with S3 access actually wrote a model artifact, verified by an
    # independent read at the destination (not just the job's own "Completed" status word).
    artifact_uri = desc_with_s3["ModelArtifacts"]["S3ModelArtifacts"]
    _, _, artifact_key = artifact_uri.partition(f"s3://{bucket}/")
    s3.head_object(Bucket=bucket, Key=artifact_key)


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _linear_learner_image(region: str) -> str:
    account = _LINEAR_LEARNER_ACCOUNT_BY_REGION.get(region)
    if not account:
        raise AssertionError(
            f"no hardcoded linear-learner built-in-algorithm ECR account for region {region!r}"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _tiny_binary_csv() -> bytes:
    rows = []
    for i in range(20):
        label = i % 2
        f1 = 0.1 + 0.01 * i if label else 0.9 - 0.01 * i
        f2 = 0.2 + 0.01 * i if label else 0.8 - 0.01 * i
        rows.append(f"{label},{f1:.3f},{f2:.3f}")
    return ("\n".join(rows) + "\n").encode("utf-8")


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


def _safe_stop_training_job(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        desc = sm.describe_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    if desc["TrainingJobStatus"] in ("InProgress", "Stopping"):
        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as exc:
            # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
            if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise
        return
    # Terminal already (this check waits for a terminal state before returning) -- SageMaker
    # keeps training-job metadata forever otherwise; DeleteTrainingJob is the only way to reclaim it.
    try:
        sm.delete_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _safe_delete_trial_component(ctx, job_name: str) -> None:
    # CreateTrainingJob auto-creates a same-lifetime "<job>-aws-training-job" trial component for
    # SageMaker Experiments tracking; DeleteTrainingJob does not remove it, so it is reclaimed here.
    sm = ctx.client("sagemaker")
    name = f"{job_name}-aws-training-job"
    try:
        sm.delete_trial_component(TrialComponentName=name)
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
