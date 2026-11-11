"""cfn-deploy-sagemaker-endpoint-config-s3-kms-negative."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-endpoint-config-s3-kms-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

# Built-in XGBoost algorithm image URIs; the account IDs are AWS-owned ECR registries per region.
_XGBOOST_IMAGE_BY_REGION = {
    "us-east-1": "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.7-1",
    "us-west-2": "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-xgboost:1.7-1",
}

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  RoleWithDecryptName:
    Type: String
  RoleWithoutDecryptName:
    Type: String
  BucketName:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  DataKey:
    Type: AWS::KMS::Key
    Properties:
      Description: sim2real-xsvc SageMaker/S3 KMS-decrypt boundary check key
      KeyPolicy:
        Version: "2012-10-17"
        Statement:
          - Sid: EnableRootPermissions
            Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${AWS::AccountId}:root"
            Action: "kms:*"
            Resource: "*"
  RoleWithDecrypt:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleWithDecryptName
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: S3AndKmsAccess
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
              - Effect: Allow
                Action:
                  - kms:Decrypt
                Resource: !GetAtt DataKey.Arn
  RoleWithoutDecrypt:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleWithoutDecryptName
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: S3OnlyAccess
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
  KeyIdOut:
    Value: !Ref DataKey
  RoleWithDecryptArn:
    Value: !GetAtt RoleWithDecrypt.Arn
  RoleWithoutDecryptArn:
    Value: !GetAtt RoleWithoutDecrypt.Arn
  BucketNameOut:
    Value: !Ref BucketName
"""


@tags(
    "axis:negative-delivery",
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
    """A Processing job whose role can read the S3 object but lacks kms:Decrypt on its CMK fails
    and writes no output, while an identical job with a role that has kms:Decrypt completes and
    writes one."""
    image = _XGBOOST_IMAGE_BY_REGION.get(ctx.region)
    if image is None:
        raise AssertionError(
            f"no verified built-in XGBoost registry-path account ID recorded for region "
            f"{ctx.region!r} (only us-east-1/us-west-2 verified)."
        )

    role_with_name = ctx.unique_name("sim2real-xsvc-sm-role-kms-")
    role_without_name = ctx.unique_name("sim2real-xsvc-sm-role-nokms-")
    bucket_name = ctx.unique_name("sim2real-xsvc-sm-bkt-")

    stack = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "RoleWithDecryptName": role_with_name,
            "RoleWithoutDecryptName": role_without_name,
            "BucketName": bucket_name,
        },
    )
    key_id = stack["outputs"]["KeyIdOut"]
    role_with_arn = stack["outputs"]["RoleWithDecryptArn"]
    role_without_arn = stack["outputs"]["RoleWithoutDecryptArn"]
    bucket = stack["outputs"]["BucketNameOut"]

    s3 = ctx.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key="secure-input/data.csv",
        Body=b"a,b\n1,2\n",
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=key_id,
    )
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    sagemaker = ctx.client("sagemaker")

    # A Processing job (not an Endpoint) isolates the S3+KMS fetch: its container step can be
    # overridden, so no serving-readiness health check confounds the failure.
    def _submit(role_arn: str, output_prefix: str) -> str:
        job_name = ctx.unique_name("sim2real-xsvc-sm-proc-")
        sagemaker.create_processing_job(
            ProcessingJobName=job_name,
            RoleArn=role_arn,
            AppSpecification={
                "ImageUri": image,
                "ContainerEntrypoint": ["/bin/bash", "-c"],
                "ContainerArguments": [
                    "cat /opt/ml/processing/input/data.csv > /opt/ml/processing/output/out.csv"
                ],
            },
            ProcessingInputs=[
                {
                    "InputName": "input",
                    "S3Input": {
                        "S3Uri": f"s3://{bucket}/secure-input/",
                        "LocalPath": "/opt/ml/processing/input",
                        "S3DataType": "S3Prefix",
                        "S3InputMode": "File",
                        "S3DataDistributionType": "FullyReplicated",
                    },
                }
            ],
            ProcessingOutputConfig={
                "Outputs": [
                    {
                        "OutputName": "output",
                        "S3Output": {
                            "S3Uri": f"s3://{bucket}/{output_prefix}/",
                            "LocalPath": "/opt/ml/processing/output",
                            "S3UploadMode": "EndOfJob",
                        },
                    }
                ]
            },
            ProcessingResources={
                "ClusterConfig": {
                    "InstanceType": "ml.m5.large",
                    "InstanceCount": 1,
                    "VolumeSizeInGB": 5,
                }
            },
            StoppingCondition={"MaxRuntimeInSeconds": 600},
            Tags=_xsvc_tags_kv(),
        )

        ctx.on_cleanup(lambda: _best_effort_delete_processing_job(ctx, job_name))
        ctx.on_cleanup(lambda: _safe_delete_trial_component(ctx, job_name))
        return job_name

    positive_job = _submit(role_with_arn, "secure-output-positive")
    negative_job = _submit(role_without_arn, "secure-output-negative")

    positive_described = _poll_until(
        lambda: sagemaker.describe_processing_job(ProcessingJobName=positive_job),
        lambda d: d["ProcessingJobStatus"] in {"Completed", "Failed", "Stopped"},
        timeout_s=900.0,
        interval_s=10.0,
        description=f"positive-control processing job {positive_job} to reach terminal status",
    )
    negative_described = _poll_until(
        lambda: sagemaker.describe_processing_job(ProcessingJobName=negative_job),
        lambda d: d["ProcessingJobStatus"] in {"Completed", "Failed", "Stopped"},
        timeout_s=900.0,
        interval_s=10.0,
        description=f"negative processing job {negative_job} to reach terminal status",
    )

    assert positive_described["ProcessingJobStatus"] == "Completed", (
        positive_described.get("FailureReason")
    )
    s3.head_object(Bucket=bucket, Key="secure-output-positive/out.csv")

    assert negative_described["ProcessingJobStatus"] == "Failed", negative_described

    listing = s3.list_objects_v2(Bucket=bucket, Prefix="secure-output-negative/")
    assert listing.get("KeyCount", 0) == 0, (
        f"expected no output written under secure-output-negative/ for the role lacking "
        f"kms:Decrypt, found {listing.get('KeyCount', 0)} object(s): "
        f"{[o['Key'] for o in listing.get('Contents', [])]}"
    )


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


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(s in msg for s in ("not found", "does not exist", "could not find"))
    )


def _best_effort_delete_processing_job(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        status = sm.describe_processing_job(ProcessingJobName=job_name)[
            "ProcessingJobStatus"
        ]
        if status in ("InProgress", "Stopping"):
            sm.stop_processing_job(ProcessingJobName=job_name)
            _poll_until(
                lambda: sm.describe_processing_job(ProcessingJobName=job_name)["ProcessingJobStatus"],
                lambda s: s not in ("InProgress", "Stopping"),
                timeout_s=300.0,
                interval_s=2.0,
                description=f"stop processing job {job_name}",
            )
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    try:
        sm.delete_processing_job(ProcessingJobName=job_name)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _safe_delete_trial_component(ctx, job_name: str) -> None:
    # CreateProcessingJob auto-creates a "<job>-aws-processing-job" trial component that
    # DeleteProcessingJob does not remove.
    sm = ctx.client("sagemaker")
    try:
        sm.delete_trial_component(TrialComponentName=f"{job_name}-aws-processing-job")
    except ClientError as exc:
        if not _gone(exc):
            raise


def _empty_bucket(ctx, bucket: str) -> None:
    # CloudFormation cannot delete a non-empty bucket; this cleanup runs before the stack delete.
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
