"""deploy-cfn-sagemaker-notebook-instance-role-s3-access-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-sagemaker-notebook-instance-role-s3-access-positive"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  CallerArn:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
  ExecRole:
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
        - PolicyName: s3-read-access
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
  Notebook:
    Type: AWS::SageMaker::NotebookInstance
    Properties:
      InstanceType: ml.t3.medium
      RoleArn: !GetAtt ExecRole.Arn
Outputs:
  BucketName:
    Value: !Ref DataBucket
  RoleArn:
    Value: !GetAtt ExecRole.Arn
  NotebookInstanceName:
    Value: !GetAtt Notebook.NotebookInstanceName
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed NotebookInstance's attached IAM role can list/get objects from the
    stack's co-deployed S3 bucket, proving the role and bucket are wired together correctly
    across the CFN dependency graph (Notebook -> ExecRole -> DataBucket)."""
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    stack = _deploy_cfn(ctx, _TEMPLATE, parameters={"CallerArn": caller_arn}, timeout_s=900)
    bucket = stack["outputs"]["BucketName"]
    role_arn = stack["outputs"]["RoleArn"]
    notebook_name = stack["outputs"]["NotebookInstanceName"]

    sm = ctx.client("sagemaker")

    def _stop_and_wait() -> None:
        try:
            status = sm.describe_notebook_instance(NotebookInstanceName=notebook_name)[
                "NotebookInstanceStatus"
            ]
        except ClientError as exc:
            if not _gone(exc):
                raise
            return
        if status in ("Stopped", "Failed"):
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
            lambda s: s in ("Stopped", "Failed"),
            timeout_s=300,
            interval_s=10.0,
            description=f"stop notebook {notebook_name}",
        )

    ctx.on_cleanup(_stop_and_wait)

    status = _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=notebook_name)[
            "NotebookInstanceStatus"
        ],
        lambda s: s in ("InService", "Failed"),
        timeout_s=600,
        interval_s=15.0,
        description=f"notebook {notebook_name} InService",
    )
    assert status == "InService", f"notebook {notebook_name} ended in status {status!r}"

    desc = sm.describe_notebook_instance(NotebookInstanceName=notebook_name)
    assert desc["RoleArn"] == role_arn, f"expected RoleArn {role_arn!r}, got {desc['RoleArn']!r}"

    s3 = ctx.client("s3")
    key = "data/hello.txt"
    body = b"payload-for-notebook-role"
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    def _empty_bucket() -> None:
        # DataBucket is a plain AWS::S3::Bucket with no DeletionPolicy -- CloudFormation
        # refuses to delete a non-empty bucket, which would otherwise strand the stack in
        # DELETE_FAILED with this object still in it.
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )

    ctx.on_cleanup(_empty_bucket)

    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-notebook-role-test")[
        "Credentials"
    ]
    scoped_s3 = ctx.client(
        "s3",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    listing = scoped_s3.list_objects_v2(Bucket=bucket, Prefix="data/")
    keys = [o["Key"] for o in listing.get("Contents", [])]
    assert key in keys, f"expected {key!r} in role-scoped listing, got {keys!r}"

    obj = scoped_s3.get_object(Bucket=bucket, Key=key)
    actual_body = obj["Body"].read()
    assert actual_body == body, f"expected body {body!r}, got {actual_body!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
