"""deploy-cfn-sagemaker-bucket-policy-denies-role-negative."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-sagemaker-bucket-policy-denies-role-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  CallerArn:
    Type: String
Resources:
  ArtifactBucket:
    Type: AWS::S3::Bucket
  RoleDenied:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
          - Effect: Allow
            Principal:
              AWS: !Ref CallerArn
            Action: sts:AssumeRole
      Policies:
        - PolicyName: broad-s3-read
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt ArtifactBucket.Arn
                  - !Sub '${ArtifactBucket.Arn}/*'
  RoleAllowed:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
          - Effect: Allow
            Principal:
              AWS: !Ref CallerArn
            Action: sts:AssumeRole
      Policies:
        - PolicyName: broad-s3-read
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt ArtifactBucket.Arn
                  - !Sub '${ArtifactBucket.Arn}/*'
  DenyBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref ArtifactBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: DenySageMakerExecRole
            Effect: Deny
            Principal:
              AWS: !GetAtt RoleDenied.Arn
            Action: s3:GetObject
            Resource: !Sub '${ArtifactBucket.Arn}/*'
Outputs:
  BucketName:
    Value: !Ref ArtifactBucket
  RoleDeniedArn:
    Value: !GetAtt RoleDenied.Arn
  RoleAllowedArn:
    Value: !GetAtt RoleAllowed.Arn
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation bucket policy that denies s3:GetObject to one SageMaker role refuses that role's
    read with AccessDenied and the exact explicit-deny message although its identity policy allows it,
    while a sibling role not named in the deny reads the same artifact bytes."""
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    stack = _deploy_cfn(ctx, _TEMPLATE, parameters={"CallerArn": caller_arn}, timeout_s=180)
    bucket = stack["outputs"]["BucketName"]
    role_denied_arn = stack["outputs"]["RoleDeniedArn"]
    role_allowed_arn = stack["outputs"]["RoleAllowedArn"]

    s3 = ctx.client("s3")
    key = "model/artifact.bin"
    body = b"protected-model-bytes"
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    # CloudFormation refuses to delete a non-empty AWS::S3::Bucket, so the object must be
    # gone before the stack teardown reaches it (ctx.on_cleanup runs LIFO: this fires first).
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    def _assume_s3(role_arn: str, session: str):
        creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session)["Credentials"]
        return ctx.client(
            "s3",
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            },
        )

    # Positive control: a role NOT targeted by the Deny statement, with the same identity
    # policy, retrieves the object normally.
    allowed_s3 = _assume_s3(role_allowed_arn, "sim2real-allowed")
    allowed_body = allowed_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert allowed_body == body, (
        f"positive control (role not named in the Deny) expected {body!r}, got {allowed_body!r}"
    )

    # Negative: the explicitly denied role gets AccessDenied despite its IAM allow.
    denied_s3 = _assume_s3(role_denied_arn, "sim2real-denied")
    error = _client_error(lambda: denied_s3.get_object(Bucket=bucket, Key=key))
    assert error.get("Code") == "AccessDenied", (
        f"expected the bucket-policy Deny to reject the named role with AccessDenied, got {error!r}"
    )
    denied_role_name = role_denied_arn.rsplit("/", 1)[-1]
    assert error.get("Message") == (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{denied_role_name}/sim2real-denied is not "
        f'authorized to perform: s3:GetObject on resource: "arn:aws:s3:::{bucket}/{key}" with an '
        "explicit deny in a resource-based policy"
    ), error

    # Effect absent: the deny blocked *access*, not the object itself -- it is still there,
    # untouched, readable by an unaffected identity.
    control_body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert control_body == body, (
        f"object itself must be unaffected by the Deny; expected {body!r}, got {control_body!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _client_error(fn) -> dict:
    """Call fn(); return its Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"expected s3:GetObject to be denied by the bucket policy, but it SUCCEEDED: {result!r}"
    )


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


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
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
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
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
