"""cfn-deploy-sagemaker-notebook-instance-s3-role-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-notebook-instance-s3-role-positive"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

_NOTEBOOK_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketName:
    Type: String
  NotebookInstanceName:
    Type: String
  CallerArn:
    Type: String
Resources:
  ExecutionRole:
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
        - PolicyName: BucketAccess
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
                Resource:
                  - !Sub "arn:aws:s3:::${BucketName}"
                  - !Sub "arn:aws:s3:::${BucketName}/*"
  NotebookInstance:
    Type: AWS::SageMaker::NotebookInstance
    Properties:
      NotebookInstanceName: !Ref NotebookInstanceName
      InstanceType: ml.t3.medium
      RoleArn: !GetAtt ExecutionRole.Arn
Outputs:
  NotebookInstanceName:
    # AWS::SageMaker::NotebookInstance's Ref returns the notebook ARN, not the name -- so the
    # name must come back through the parameter we set it from, not through !Ref NotebookInstance.
    Value: !Ref NotebookInstanceName
  RoleArn:
    Value: !GetAtt ExecutionRole.Arn
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed NotebookInstance's IAM role, which trusts sagemaker.amazonaws.com and was
    wired up in the same stack, actually grants read access to the designated S3 bucket (and
    nothing beyond what was granted) once the notebook has reached InService."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    probe_key = "probe/object.txt"
    probe_body = b"sim2real-notebook-role-probe"
    s3.put_object(Bucket=bucket, Key=probe_key, Body=probe_body)
    notebook_name = _xname(ctx, "nb")

    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]

    result = _deploy_cfn(
        ctx,
        _NOTEBOOK_TEMPLATE,
        parameters={
            "BucketName": bucket,
            "NotebookInstanceName": notebook_name,
            "CallerArn": caller_arn,
        },
        timeout_s=900.0,
    )
    assert result["outputs"]["NotebookInstanceName"] == notebook_name, (
        f"expected NotebookInstanceName output {notebook_name!r}, "
        f"got {result['outputs']['NotebookInstanceName']!r}"
    )
    role_arn = result["outputs"]["RoleArn"]

    sm = ctx.client("sagemaker")
    described = _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=notebook_name),
        lambda r: r["NotebookInstanceStatus"] == "InService",
        timeout_s=120.0,
        interval_s=10.0,
        description=f"notebook instance {notebook_name} InService",
    )
    assert described["RoleArn"] == role_arn, (
        f"expected notebook RoleArn {role_arn!r}, got {described['RoleArn']!r}"
    )

    # Real enforcement, not advisory simulation: assume the exact role the stack wired to the
    # notebook and issue the actual S3 calls as that role, at the destination.
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
    fetched = scoped_s3.get_object(Bucket=bucket, Key=probe_key)["Body"].read()
    assert fetched == probe_body, f"expected {probe_body!r} via the notebook role, got {fetched!r}"

    # The role was granted GetObject/ListBucket only -- an action outside that grant must be
    # REFUSED for real, not merely predicted absent by policy simulation.
    try:
        scoped_s3.delete_object(Bucket=bucket, Key=probe_key)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "AccessDenied", f"expected AccessDenied, got {code}"
        role_name = role_arn.rsplit("/", 1)[-1]
        assert e.response["Error"]["Message"] == (
            f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/sim2real-notebook-role-test "
            f'is not authorized to perform: s3:DeleteObject on resource: "arn:aws:s3:::{bucket}/'
            f'{probe_key}" because no identity-based policy allows the s3:DeleteObject action'
        ), e.response["Error"]
    else:
        raise AssertionError(
            "expected DeleteObject to be denied for the notebook role, but it succeeded"
        )

    # Effect-absent, via an independent read at the destination: the probe object must still
    # be exactly what was written -- the denied delete did not partially take effect.
    still_there = s3.get_object(Bucket=bucket, Key=probe_key)["Body"].read()
    assert still_there == probe_body, (
        f"expected probe object to survive the denied delete unchanged, got {still_there!r}"
    )


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
        timeout_s=900,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        events = cfn.describe_stack_events(StackName=name)["StackEvents"]
        reasons = "; ".join(
            f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
            for e in events
            if e.get("ResourceStatus", "").endswith("FAILED")
        )
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}: {reasons}"[:2000])
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bkt")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
