"""cfn-deploy-sagemaker-execution-role-trusts-s3-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

CHECK = "cfn-deploy-sagemaker-execution-role-trusts-s3-positive"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

from behavioral_harness import tags

# Best-known public registry paths for the SageMaker built-in XGBoost algorithm container (see the
# SageMaker Python SDK's image_uris config / AWS's "Docker Registry Paths and Example Code" page).
# CreateModel validates that the passed role can actually pull the image, so a made-up ECR path
# always fails with "cannot pull ... Ensure ... image was granted pull permission" -- a real,
# publicly-pullable built-in-algorithm image is required to isolate the trust/S3 permission boundary
# this check targets. Limited to regions verified with high confidence; any other region fails
# honestly (see the AssertionError below) rather than risk a false FAIL from a wrong account ID.
# This never skips -- a check never skips.
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
              Service:
                - sagemaker.amazonaws.com
                - s3.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: S3ModelArtifactAccess
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
                Resource:
                  - !Sub "arn:aws:s3:::${BucketName}"
                  - !Sub "arn:aws:s3:::${BucketName}/*"
Outputs:
  RoleArn:
    Value: !GetAtt ExecRole.Arn
  BucketNameOut:
    Value: !Ref BucketName
"""


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:deploy", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel accepts a CloudFormation-created role that trusts both sagemaker.amazonaws.com and
    s3.amazonaws.com, DescribeModel echoes the role ARN and ModelDataUrl, and IAM policy simulation of
    the role's attached policy allows the declared S3 read."""
    image = _XGBOOST_IMAGE_BY_REGION.get(ctx.region)
    if image is None:
        raise AssertionError(
            f"no verified built-in XGBoost registry-path account ID recorded for region "
            f"{ctx.region!r} (only us-east-1/us-west-2 verified); would need that region's "
            "account ID from the SageMaker built-in algorithm Docker registry table to run."
        )

    role_name = ctx.unique_name("sim2real-xsvc-sm-role-")
    bucket_name = ctx.unique_name("sim2real-xsvc-sm-bkt-")

    stack = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"RoleName": role_name, "BucketName": bucket_name},
    )
    role_arn = stack["outputs"]["RoleArn"]
    bucket = stack["outputs"]["BucketNameOut"]

    iam = ctx.client("iam")
    trust_doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    principals = trust_doc["Statement"][0]["Principal"]["Service"]
    assert set(principals) == {"sagemaker.amazonaws.com", "s3.amazonaws.com"}

    sagemaker = ctx.client("sagemaker")
    model_name = ctx.unique_name("sim2real-xsvc-sm-model-")
    model_data_url = f"s3://{bucket}/model/model.tar.gz"

    # CreateModel validates that the ModelDataUrl object actually exists (independent of the
    # role/trust boundary this check targets), so a real artifact must be present first.
    s3 = ctx.client("s3")
    model_key = "model/model.tar.gz"
    s3.put_object(Bucket=bucket, Key=model_key, Body=b"sim2real-xsvc-fake-artifact")
    # CloudFormation cannot delete a non-empty bucket -- the stack would end DELETE_FAILED and
    # leak the bucket (and the object) forever. Registered after the stack's own on_cleanup, so
    # LIFO teardown empties the bucket before the stack delete is attempted.
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=model_key))

    def _create_model():
        sagemaker.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": image, "ModelDataUrl": model_data_url},
            Tags=_xsvc_tags_kv(),
        )
        return True

    # IAM role trust/permission propagation to SageMaker's control plane can lag a few
    # seconds behind CreateRole returning, even though the CFN stack already reports
    # CREATE_COMPLETE. Retry CreateModel on the transient "cannot be assumed" validation
    # error instead of failing on the very first attempt.
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
    assert described["ExecutionRoleArn"] == role_arn
    assert described["PrimaryContainer"]["ModelDataUrl"] == model_data_url

    sim = iam.simulate_principal_policy(
        PolicySourceArn=role_arn,
        ActionNames=["s3:GetObject"],
        ResourceArns=[f"arn:aws:s3:::{bucket}/model/model.tar.gz"],
    )
    assert sim["EvaluationResults"][0]["EvalDecision"] == "allowed"


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
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
