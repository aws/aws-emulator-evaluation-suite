"""cfn-deploy-sagemaker-model-s3-artifact-reference-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-model-s3-artifact-reference-positive"
GROUP = "arn-resolution"
SERVICES = ["s3", "sagemaker"]

_BUCKET_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketName:
    Type: String
  RoleName:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  ModelRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: s3-scoped-access
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt DataBucket.Arn
                  - !Sub '${DataBucket.Arn}/*'
Outputs:
  BucketName:
    Value: !Ref DataBucket
  RoleArn:
    Value: !GetAtt ModelRole.Arn
"""

# A SageMaker::Model resource's ModelDataUrl is validated by the CloudFormation resource
# handler AT CREATE TIME (CreateModel via CFN 404s with HandlerErrorCode=NotFound if the S3
# object does not already exist) -- unlike a raw boto3 CreateModel call. So the Model must live
# in a SEPARATE stack, deployed only after the bucket exists and the real artifact object has
# been uploaded to it.
_MODEL_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketName:
    Type: String
  RoleArn:
    Type: String
  ImageUri:
    Type: String
  ModelDataKey:
    Type: String
Resources:
  Model:
    Type: AWS::SageMaker::Model
    Properties:
      ExecutionRoleArn: !Ref RoleArn
      PrimaryContainer:
        Image: !Ref ImageUri
        ModelDataUrl: !Sub 's3://${BucketName}/${ModelDataKey}'
Outputs:
  ModelArn:
    Value: !Ref Model
"""

_MODEL_DATA_KEY = "model-artifacts/model.tar.gz"


def _model_name_from_arn(arn: str) -> str:
    # AWS::SageMaker::Model's Ref returns the ARN (arn:aws:sagemaker:<region>:<acct>:model/<name>),
    # not the plain name -- unlike most other CFN resource types.
    return arn.rsplit("/", 1)[-1]


# AWS-published, per-region SageMaker built-in-algorithm ECR registry account IDs -- fixed and
# identical for every account in a given region (not a per-account quota), so pinning them here is
# part of the contract rather than an account-specific assumption.
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


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SageMaker Model's ModelDataUrl, built inside the template with Fn::Sub against a
    stack-provisioned bucket, resolves to the exact S3 location that a real object lives at."""
    image = _linear_learner_image(ctx.region)
    bucket_name = _xname(ctx, "modelbucket")
    role_name = _xname(ctx, "modelrole")

    bucket_result = _deploy_cfn(
        ctx,
        _BUCKET_TEMPLATE,
        parameters={"BucketName": bucket_name, "RoleName": role_name},
        timeout_s=600.0,
    )
    assert bucket_result["outputs"]["BucketName"] == bucket_name, (
        "bucket stack Outputs.BucketName", bucket_result["outputs"].get("BucketName"), bucket_name
    )
    role_arn = bucket_result["outputs"]["RoleArn"]

    s3 = ctx.client("s3")
    body = b"placeholder-model-bytes-for-arn-resolution-check"
    s3.put_object(Bucket=bucket_name, Key=_MODEL_DATA_KEY, Body=body)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    model_result = _deploy_cfn(
        ctx,
        _MODEL_TEMPLATE,
        parameters={
            "BucketName": bucket_name,
            "RoleArn": role_arn,
            "ImageUri": image,
            "ModelDataKey": _MODEL_DATA_KEY,
        },
        timeout_s=600.0,
    )
    model_name = _model_name_from_arn(model_result["outputs"]["ModelArn"])

    sm = ctx.client("sagemaker")
    desc = sm.describe_model(ModelName=model_name)
    resolved_url = desc["PrimaryContainer"]["ModelDataUrl"]
    expected_url = f"s3://{bucket_name}/{_MODEL_DATA_KEY}"
    assert resolved_url == expected_url, (resolved_url, expected_url)

    key = resolved_url[len(f"s3://{bucket_name}/"):]
    fetched = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
    assert fetched == body, ("s3 object bytes fetched through resolved ModelDataUrl", fetched, body)


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _first_failure_reason(cfn, stack_name: str) -> str:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except ClientError as e:
        return f"<could not fetch events: {e}>"
    for ev in events:
        if ev.get("ResourceStatus", "").endswith("_FAILED"):
            return (
                f"{ev.get('LogicalResourceId')} ({ev.get('ResourceType')}): "
                f"{ev.get('ResourceStatusReason')}"
            )
    return "<no _FAILED event found>"


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
    max_attempts=3,
) -> dict[str, Any]:
    # SageMaker resources (Model/Endpoint) that reference a role created earlier in the SAME
    # stack can transiently fail CreateModel/CreateEndpointConfig with an AccessDenied-style
    # error because the new role's trust policy has not finished propagating through IAM's
    # eventually-consistent replication yet. CloudFormation does not retry this itself for
    # SageMaker resource types, so on a rollback we delete the failed stack and retry the
    # whole create from scratch (a fresh attempt several seconds later almost always succeeds
    # once the role is usable) instead of treating the transient failure as terminal.
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
    cleanup_registered = False
    last_status = None
    for attempt in range(1, max_attempts + 1):
        stack_id = cfn.create_stack(**kwargs)["StackId"]
        if not cleanup_registered:
            ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
            cleanup_registered = True
        status = _poll_until(
            lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
            lambda s: s
            in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
            timeout_s=timeout_s,
            interval_s=5.0,
            description=f"CFN stack {name} (attempt {attempt}/{max_attempts})",
        )
        if status == "CREATE_COMPLETE":
            stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
            outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
            return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}
        last_status = status
        last_reason = _first_failure_reason(cfn, name)
        if attempt < max_attempts:
            _delete_stack_and_wait(ctx, name)
            time.sleep(2.0)
    raise AssertionError(
        f"Stack {name} failed to reach CREATE_COMPLETE after {max_attempts} attempts;"
        f" last status {last_status}; first failure reason: {last_reason}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
