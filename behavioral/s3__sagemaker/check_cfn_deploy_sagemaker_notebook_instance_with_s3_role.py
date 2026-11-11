"""cfn-deploy-sagemaker-notebook-instance-with-s3-role."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-notebook-instance-with-s3-role"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RoleName:
    Type: String
  LifecycleName:
    Type: String
  WriteKey:
    Type: String
  VerifyKey:
    Type: String
  Payload:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
  NotebookRole:
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
                  - s3:PutObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt DataBucket.Arn
                  - !Sub '${DataBucket.Arn}/*'
  LifecycleConfig:
    Type: AWS::SageMaker::NotebookInstanceLifecycleConfig
    Properties:
      NotebookInstanceLifecycleConfigName: !Ref LifecycleName
      OnStart:
        - Content:
            Fn::Base64: !Sub |
              #!/bin/bash
              set -e
              printf '%s' "${Payload}" | aws s3 cp - "s3://${DataBucket}/${WriteKey}"
              CONTENT=$(aws s3 cp "s3://${DataBucket}/${WriteKey}" -)
              printf 'readback:%s' "$CONTENT" | aws s3 cp - "s3://${DataBucket}/${VerifyKey}"
  Notebook:
    Type: AWS::SageMaker::NotebookInstance
    DependsOn:
      - LifecycleConfig
      - NotebookRole
    Properties:
      InstanceType: ml.t3.medium
      RoleArn: !GetAtt NotebookRole.Arn
      LifecycleConfigName: !Ref LifecycleName
Outputs:
  BucketName:
    Value: !Ref DataBucket
  RoleArn:
    Value: !GetAtt NotebookRole.Arn
  NotebookName:
    Value: !GetAtt Notebook.NotebookInstanceName
"""


@tags(
    "axis:happy-path",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A stack-provisioned notebook reaches InService and its OnStart script, running as the
    notebook's execution role, writes to and reads back from the stack's S3 bucket; the check
    reads the readback marker itself as destination-side proof."""
    role_name = _xname(ctx, "nbrole")
    lifecycle_name = _xname(ctx, "nblc")
    write_key = "notebook-role-probe/write.txt"
    verify_key = "notebook-role-probe/verify.txt"
    payload = _xname(ctx, "payload")

    result = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "RoleName": role_name,
            "LifecycleName": lifecycle_name,
            "WriteKey": write_key,
            "VerifyKey": verify_key,
            "Payload": payload,
        },
        timeout_s=900.0,
    )
    outputs = result["outputs"]
    notebook_name = outputs["NotebookName"]
    bucket = outputs["BucketName"]

    sm = ctx.client("sagemaker")
    ctx.on_cleanup(lambda: _stop_notebook_and_wait(ctx, notebook_name))
    # The lifecycle script writes real objects into this CFN-managed bucket, and DeleteStack
    # cannot delete a non-empty bucket -- empty it before the stack-delete cleanup runs, or the
    # stack lands in DELETE_FAILED and both the bucket and the stack leak.
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    status = _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=notebook_name)[
            "NotebookInstanceStatus"
        ],
        lambda s: s in {"InService", "Failed"},
        timeout_s=600.0,
        interval_s=10.0,
        description=f"notebook instance {notebook_name} InService",
    )
    assert status == "InService", f"notebook instance ended in status {status!r}"

    s3 = ctx.client("s3")

    def _read(key: str) -> bytes | None:
        try:
            return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError:
            return None

    write_body = _poll_until(
        lambda: _read(write_key),
        lambda b: b is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description=f"OnStart PutObject to s3://{bucket}/{write_key} via the notebook role",
    )
    assert write_body.decode() == payload, (write_body, payload)

    verify_body = _poll_until(
        lambda: _read(verify_key),
        lambda b: b is not None,
        timeout_s=60.0,
        interval_s=5.0,
        description=f"OnStart GetObject readback recorded at s3://{bucket}/{verify_key}",
    )
    assert verify_body.decode() == f"readback:{payload}", (verify_body, payload)


# ===== helpers =====
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


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    if objs:
        s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})


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
