"""cfn-deploy-sagemaker-model-s3-artifact-stack-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-model-s3-artifact-stack-positive"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

_MODEL_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketName:
    Type: String
  ModelDataKey:
    Type: String
  ModelName:
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
      Policies:
        - PolicyName: ModelArtifactRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                Resource: !Sub "arn:aws:s3:::${BucketName}/${ModelDataKey}"
  Model:
    Type: AWS::SageMaker::Model
    Properties:
      ModelName: !Ref ModelName
      ExecutionRoleArn: !GetAtt ExecutionRole.Arn
      PrimaryContainer:
        # A real, publicly-pullable SageMaker built-in algorithm image (kmeans, us-west-2
        # registry account) so CreateModel's image-pull validation succeeds. This test only
        # needs a model that resolves to a real image + the S3 artifact; it never runs inference.
        Image: "174872318107.dkr.ecr.us-west-2.amazonaws.com/kmeans:1"
        ModelDataUrl: !Sub "s3://${BucketName}/${ModelDataKey}"
Outputs:
  ModelName:
    # AWS::SageMaker::Model's Ref returns the model ARN, not the name (unlike most other
    # resource types) -- so the name must come back through the parameter we set it from,
    # not through !Ref Model.
    Value: !Ref ModelName
  RoleArn:
    Value: !GetAtt ExecutionRole.Arn
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-created SageMaker model reports the stack's model name, a ModelDataUrl equal to the
    artifact uploaded before the stack was created (its bytes read back from S3) and the ExecutionRoleArn
    of the role the same stack created."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    model_key = "artifacts/model.tar.gz"
    artifact_body = f"sim2real-fake-model-artifact-{ctx.unique_name('payload-')}".encode("utf-8")
    s3.put_object(Bucket=bucket, Key=model_key, Body=artifact_body)
    model_name = _xname(ctx, "model")

    result = _deploy_cfn(
        ctx,
        _MODEL_TEMPLATE,
        parameters={"BucketName": bucket, "ModelDataKey": model_key, "ModelName": model_name},
    )
    assert result["outputs"]["ModelName"] == model_name, (
        f"expected stack output ModelName {model_name!r}, got {result['outputs'].get('ModelName')!r}"
    )
    role_arn = result["outputs"]["RoleArn"]

    sm = ctx.client("sagemaker")
    described = sm.describe_model(ModelName=model_name)
    expected_url = f"s3://{bucket}/{model_key}"
    actual_url = described["PrimaryContainer"]["ModelDataUrl"]
    assert actual_url == expected_url, f"expected ModelDataUrl {expected_url!r}, got {actual_url!r}"
    assert described["ExecutionRoleArn"] == role_arn, (
        f"expected ExecutionRoleArn {role_arn!r} (from the stack's own GetAtt), "
        f"got {described['ExecutionRoleArn']!r}"
    )

    # Resolve the ModelDataUrl back into bucket/key and prove it is the SAME object we uploaded
    # before the stack existed, not merely a same-shaped string.
    resolved = described["PrimaryContainer"]["ModelDataUrl"]
    assert resolved.startswith("s3://"), f"expected an s3:// ModelDataUrl, got {resolved!r}"
    resolved_bucket, resolved_key = resolved[len("s3://"):].split("/", 1)
    fetched = s3.get_object(Bucket=resolved_bucket, Key=resolved_key)
    fetched_body = fetched["Body"].read()
    assert fetched_body == artifact_body, (
        f"expected the resolved s3://{resolved_bucket}/{resolved_key} object to contain the "
        f"exact {len(artifact_body)}-byte artifact uploaded before stack creation, "
        f"got {len(fetched_body)} different bytes"
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
        timeout_s=120,
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
    # CreateBucket rejects a LocationConstraint of "us-east-1" outright -- that region is the
    # one case where the constraint must be omitted rather than set, regardless of ctx.region.
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
