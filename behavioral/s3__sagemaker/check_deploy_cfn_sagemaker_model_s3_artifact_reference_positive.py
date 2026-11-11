"""deploy-cfn-sagemaker-model-s3-artifact-reference-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-sagemaker-model-s3-artifact-reference-positive"
GROUP = "arn-resolution"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ExecutionRoleArn:
    Type: String
  BucketName:
    Type: String
Resources:
  Model:
    Type: AWS::SageMaker::Model
    Properties:
      ExecutionRoleArn: !Ref ExecutionRoleArn
      PrimaryContainer:
        Image: !Sub '763104351884.dkr.ecr.${AWS::Region}.amazonaws.com/pytorch-inference:2.1.0-cpu-py310'
        ModelDataUrl: !Sub 's3://${BucketName}/artifacts/model.tar.gz'
Outputs:
  ModelName:
    Value: !GetAtt Model.ModelName
"""


def _create_verified_sagemaker_role(ctx, *, bucket: str, key: str) -> str:
    """Create an IAM role trusting sagemaker.amazonaws.com and block until SageMaker's
    CreateModel actually accepts it against a REAL s3://bucket/key -- a freshly created
    role is not immediately usable (IAM propagation lag), so this retries a throwaway
    probe model (pointed at the real, already-uploaded artifact) until it succeeds."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    import json as _json

    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust_policy),
        Tags=_xsvc_tags_kv(),
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    policy_name = f"{role_name}-s3-access"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=_json.dumps(s3_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    sm = ctx.client("sagemaker")
    probe_image = "763104351884.dkr.ecr.{}.amazonaws.com/pytorch-inference:2.1.0-cpu-py310".format(
        ctx.client("s3").meta.region_name
    )
    model_data_url = f"s3://{bucket}/{key}"

    last_error: dict[str, str] = {}

    def _probe():
        probe_name = _xname(ctx, "probe-model")
        try:
            sm.create_model(
                ModelName=probe_name,
                ExecutionRoleArn=role_arn,
                PrimaryContainer={"Image": probe_image, "ModelDataUrl": model_data_url},
            )
        except ClientError as exc:
            last_error["code"] = exc.response.get("Error", {}).get("Code", "")
            last_error["message"] = exc.response.get("Error", {}).get("Message", "")
            return False
        sm.delete_model(ModelName=probe_name)
        return True

    try:
        _poll_until(
            _probe,
            lambda ok: ok,
            timeout_s=150,
            interval_s=5.0,
            description=f"IAM role {role_name} usable by sagemaker:CreateModel",
        )
    except AssertionError as exc:
        raise AssertionError(f"{exc} -- last error: {last_error}") from exc
    return role_arn


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-created SageMaker model's ModelDataUrl (built with Fn::Sub over the bucket name)
    parses to exactly the deployed bucket and the uploaded key, and reading that object returns the
    uploaded bytes and length."""
    s3 = ctx.client("s3")
    bucket = _xname(ctx, "bucket").rstrip("-")
    region = s3.meta.region_name
    if region == "us-east-1":
        # Not a region pin: S3's CreateBucket rejects an explicit LocationConstraint for
        # the us-east-1 default region, so this branches on ctx.region's own value, it does
        # not hardcode which region the check runs in.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    key = "artifacts/model.tar.gz"
    body = b"fake-model-artifact-bytes"
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    role_arn = _create_verified_sagemaker_role(ctx, bucket=bucket, key=key)
    stack = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"ExecutionRoleArn": role_arn, "BucketName": bucket},
        timeout_s=300,
    )
    model_name = stack["outputs"]["ModelName"]

    sm = ctx.client("sagemaker")
    desc = sm.describe_model(ModelName=model_name)
    model_data_url = desc["PrimaryContainer"]["ModelDataUrl"]
    assert model_data_url.startswith("s3://")

    parsed_bucket, _, parsed_key = model_data_url[len("s3://"):].partition("/")
    assert parsed_bucket == bucket
    assert parsed_key == key

    head = s3.head_object(Bucket=parsed_bucket, Key=parsed_key)
    assert head["ContentLength"] == len(body)
    fetched = s3.get_object(Bucket=parsed_bucket, Key=parsed_key)["Body"].read()
    assert fetched == body


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
