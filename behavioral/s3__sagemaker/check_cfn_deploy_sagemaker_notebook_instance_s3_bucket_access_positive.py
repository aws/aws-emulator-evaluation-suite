"""cfn-deploy-sagemaker-notebook-instance-s3-bucket-access-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-notebook-instance-s3-bucket-access-positive"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  RoleName:
    Type: String
  BucketName:
    Type: String
  NotebookName:
    Type: String
  LifecycleName:
    Type: String
  MarkerKey:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  NotebookRole:
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
        - PolicyName: BucketAccess
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:ListBucket
                  - s3:GetObject
                  - s3:PutObject
                Resource:
                  - !Sub "arn:aws:s3:::${BucketName}"
                  - !Sub "arn:aws:s3:::${BucketName}/*"
  LifecycleConfig:
    Type: AWS::SageMaker::NotebookInstanceLifecycleConfig
    Properties:
      NotebookInstanceLifecycleConfigName: !Ref LifecycleName
      OnStart:
        - Content:
            Fn::Base64: !Sub |
              #!/bin/bash
              set -e
              echo "notebook-role-can-access-s3" | aws s3 cp - "s3://${BucketName}/${MarkerKey}"
  NotebookInstance:
    Type: AWS::SageMaker::NotebookInstance
    DependsOn:
      - LifecycleConfig
      - NotebookRole
    Properties:
      NotebookInstanceName: !Ref NotebookName
      InstanceType: ml.t3.medium
      RoleArn: !GetAtt NotebookRole.Arn
      LifecycleConfigName: !Ref LifecycleName
Outputs:
  BucketNameOut:
    Value: !Ref BucketName
  NotebookNameOut:
    Value: !Ref NotebookName
  MarkerKeyOut:
    Value: !Ref MarkerKey
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed notebook instance whose role is granted S3 access on a bucket reaches
    InService, and its OnStart script, running as that role, writes the expected marker object,
    so the S3 grant is usable from the running resource."""
    role_name = ctx.unique_name("sim2real-xsvc-sm-role-")
    bucket_name = ctx.unique_name("sim2real-xsvc-sm-bkt-")
    notebook_name = ctx.unique_name("sim2real-xsvc-sm-nb-")
    lifecycle_name = ctx.unique_name("sim2real-xsvc-sm-lc-")
    marker_key = "lifecycle-marker/onstart.txt"

    stack = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "RoleName": role_name,
            "BucketName": bucket_name,
            "NotebookName": notebook_name,
            "LifecycleName": lifecycle_name,
            "MarkerKey": marker_key,
        },
        timeout_s=900.0,
    )
    notebook_name = stack["outputs"]["NotebookNameOut"]
    ctx.on_cleanup(lambda: _stop_notebook_and_wait(ctx, notebook_name))

    bucket = stack["outputs"]["BucketNameOut"]
    key = stack["outputs"]["MarkerKeyOut"]
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    sagemaker = ctx.client("sagemaker")
    status = sagemaker.describe_notebook_instance(
        NotebookInstanceName=notebook_name
    )["NotebookInstanceStatus"]
    assert status == "InService", f"notebook did not reach InService, got {status}"

    s3 = ctx.client("s3")

    def _probe():
        try:
            return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError:
            return None

    body = _poll_until(
        _probe,
        lambda b: b is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description=f"marker object s3://{bucket}/{key} written by notebook OnStart script",
    )
    assert body.decode().strip() == "notebook-role-can-access-s3"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


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


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(s in msg for s in ("not found", "does not exist", "could not find", "recordnotfound"))
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
        failed = [
            f"{e['LogicalResourceId']} ({e['ResourceStatus']}): {e.get('ResourceStatusReason', '')}"
            for e in cfn.describe_stack_events(StackName=name)["StackEvents"]
            if e["ResourceStatus"].endswith("FAILED")
        ]
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']} "
            f"({stack.get('StackStatusReason', 'no reason given')}); failed resources: {failed}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    try:
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs})
    except ClientError as exc:
        if not _gone(exc):
            raise


def _stop_notebook_and_wait(ctx, notebook_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        desc = sm.describe_notebook_instance(NotebookInstanceName=notebook_name)
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    if desc["NotebookInstanceStatus"] in ("Stopped", "Failed"):
        return
    try:
        sm.stop_notebook_instance(NotebookInstanceName=notebook_name)
    except ClientError as exc:
        if _gone(exc):
            return
        # Only an InService notebook accepts the stop; Pending/Updating ones go with the stack delete.
        status = sm.describe_notebook_instance(NotebookInstanceName=notebook_name)[
            "NotebookInstanceStatus"
        ]
        if status == "InService":
            raise
        if status != "Stopping":
            return
    _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=notebook_name)[
            "NotebookInstanceStatus"
        ],
        lambda s: s in {"Stopped", "Failed"},
        timeout_s=300.0,
        interval_s=10.0,
        description=f"stop notebook {notebook_name}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
