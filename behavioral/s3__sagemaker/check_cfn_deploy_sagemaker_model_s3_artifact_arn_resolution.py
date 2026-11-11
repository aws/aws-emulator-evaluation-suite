"""cfn-deploy-sagemaker-model-s3-artifact-arn-resolution."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

CHECK = "cfn-deploy-sagemaker-model-s3-artifact-arn-resolution"
GROUP = "arn-resolution"
SERVICES = ["s3", "sagemaker"]

from behavioral_harness import tags

# CreateModel (and therefore the embedded AWS::SageMaker::Model CFN resource) validates that
# the passed role can actually pull the container image, so a made-up ECR path always fails
# with "cannot pull ... Ensure ... image was granted pull permission" -- a real, publicly
# pullable built-in-algorithm image is required to isolate the ARN-resolution boundary this
# check targets. Limited to regions verified with high confidence; any other region honestly
# skips rather than risk a false FAIL from a wrong account ID.
_XGBOOST_IMAGE_BY_REGION = {
    "us-east-1": "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.7-1",
    "us-west-2": "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-xgboost:1.7-1",
}

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  RoleName:
    Type: String
  BucketName:
    Type: String
  ArtifactKey:
    Type: String
Resources:
  ArtifactBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  ExecRole:
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
        - PolicyName: S3ReadArtifact
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                Resource:
                  - !Sub "arn:aws:s3:::${BucketName}/${ArtifactKey}"
Outputs:
  RoleArn:
    Value: !GetAtt ExecRole.Arn
  BucketNameOut:
    Value: !Ref BucketName
  ArtifactKeyOut:
    Value: !Ref ArtifactKey
  ExpectedModelDataUrl:
    Value: !Sub "s3://${BucketName}/${ArtifactKey}"
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A SageMaker model built from a CloudFormation stack's Fn::Sub outputs reports, in DescribeModel, a
    ModelDataUrl equal to exactly the template's s3://bucket/key, and reading that URL from S3 returns
    the uploaded artifact bytes."""
    image = _XGBOOST_IMAGE_BY_REGION.get(ctx.region)
    if image is None:
        raise AssertionError(
            f"no verified built-in XGBoost registry-path account ID recorded for region "
            f"{ctx.region!r} (only us-east-1/us-west-2 verified); would need that region's "
            "account ID from the SageMaker built-in algorithm Docker registry table to run."
        )

    role_name = ctx.unique_name("sim2real-xsvc-sm-role-")
    bucket_name = ctx.unique_name("sim2real-xsvc-sm-bkt-")
    model_name = ctx.unique_name("sim2real-xsvc-sm-model-")
    artifact_key = "artifacts/model-v1/model.tar.gz"

    stack = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "RoleName": role_name,
            "BucketName": bucket_name,
            "ArtifactKey": artifact_key,
        },
    )
    role_arn = stack["outputs"]["RoleArn"]

    expected_url = stack["outputs"]["ExpectedModelDataUrl"]
    bucket = stack["outputs"]["BucketNameOut"]
    key = stack["outputs"]["ArtifactKeyOut"]
    assert expected_url == f"s3://{bucket}/{key}", (
        f"CFN Fn::Sub output {expected_url!r} does not match the manually-built "
        f"s3://{bucket}/{key} from the same stack's own BucketNameOut/ArtifactKeyOut outputs"
    )

    # CreateModel validates the ModelDataUrl object actually exists, so put a real artifact at
    # the exact template-declared key before resolving the ARN through DescribeModel.
    s3 = ctx.client("s3")
    artifact_body = b"sim2real-xsvc-fake-artifact"
    s3.put_object(Bucket=bucket, Key=key, Body=artifact_body)
    # ArtifactBucket is owned by the CFN stack, and CloudFormation's own S3::Bucket deletion
    # handler refuses to delete a non-empty bucket -- so the object this check put there must be
    # gone before stack teardown runs. LIFO cleanup order does that for free as long as this is
    # registered after _deploy_cfn's stack-delete cleanup.
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    sagemaker = ctx.client("sagemaker")

    def _create_model():
        sagemaker.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": image, "ModelDataUrl": expected_url},
            Tags=_xsvc_tags_kv(),
        )
        return True

    # IAM role trust/permission propagation to SageMaker's control plane can lag a few seconds
    # behind CreateRole returning, even though the CFN stack already reports CREATE_COMPLETE.
    deadline = time.monotonic() + 60.0
    last_msg = ""
    while True:
        try:
            _create_model()
            break
        except ClientError as exc:
            last_msg = str(exc)
            if "ValidationException" in last_msg and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise AssertionError(f"CreateModel failed: {last_msg[:300]}") from None
    ctx.on_cleanup(lambda: sagemaker.delete_model(ModelName=model_name))

    described = sagemaker.describe_model(ModelName=model_name)
    resolved_url = described["PrimaryContainer"]["ModelDataUrl"]
    assert resolved_url == expected_url, (
        f"DescribeModel ModelDataUrl {resolved_url!r} does not match the CFN-Sub-derived "
        f"{expected_url!r} passed to CreateModel"
    )
    assert resolved_url == f"s3://{bucket_name}/{artifact_key}", (
        f"DescribeModel ModelDataUrl {resolved_url!r} does not match the template-declared "
        f"s3://{bucket_name}/{artifact_key}"
    )

    # Resolve the returned URL back into bucket/key (not the local bucket_name/artifact_key
    # closures) and fetch through it, proving the reference is the SAME object this check
    # uploaded -- not merely a same-shaped string DescribeModel echoed back unchanged.
    assert resolved_url.startswith("s3://"), f"expected an s3:// URL, got {resolved_url!r}"
    resolved_bucket, resolved_key = resolved_url[len("s3://") :].split("/", 1)
    fetched = s3.get_object(Bucket=resolved_bucket, Key=resolved_key)["Body"].read()
    assert fetched == artifact_body, (
        f"object at the resolved ModelDataUrl ({resolved_url}) has {len(fetched)} bytes not "
        f"matching the {len(artifact_body)}-byte artifact this check uploaded there"
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
        reasons = []
        try:
            for evt in cfn.describe_stack_events(StackName=name)["StackEvents"]:
                if evt.get("ResourceStatus", "").endswith("FAILED"):
                    reasons.append(
                        f"{evt.get('LogicalResourceId')}: {evt.get('ResourceStatusReason')}"
                    )
        except ClientError:
            pass
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']}; failures: {reasons}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
