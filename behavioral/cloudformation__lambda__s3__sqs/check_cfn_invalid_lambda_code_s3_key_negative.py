"""cfn-invalid-lambda-code-s3-key-negative."""

from __future__ import annotations

import re
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-invalid-lambda-code-s3-key-negative"

GROUP = "overly-permissive"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]

_LAMBDA_S3_KEY_YAML_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda whose code lives at a caller-supplied S3 key

Parameters:
  CodeBucket:
    Type: String
  CodeKey:
    Type: String

Resources:
  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole

  LambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub 'sim2real-xsvc-badkey-fn-${AWS::StackName}'
      Runtime: python3.11
      Handler: index.lambda_handler
      Role: !GetAtt LambdaRole.Arn
      Code:
        S3Bucket: !Ref CodeBucket
        S3Key: !Ref CodeKey
"""


_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
#: The handler reason for a Code.S3Key that names no object; the request ids and SDK attempt
#: count are AWS-generated.
_MISSING_KEY_REASON = re.compile(
    r'Resource handler returned message: "Error occurred while GetObject\. S3 Error Code: '
    r"NoSuchKey\. S3 Error Message: The specified key does not exist\. \(Service: Lambda, "
    rf"Status Code: 400, Request ID: {_UUID}\) \(SDK Attempt Count: \d+\)\" "
    rf"\(RequestToken: {_UUID}, HandlerErrorCode: InvalidRequest\)"
)


def _function_name_for_stack(stack_name: str) -> str:
    return f"sim2real-xsvc-badkey-fn-{stack_name}"


def _delete_stack_and_wait(ctx, stack_id: str) -> None:
    """Delete a CFN stack by StackId and wait for DELETE_COMPLETE (teardown)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_id)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_id}",
    )


def _deploy_and_wait(
    ctx, template: str, bucket_name: str, code_key: str, timeout_s: float = 120
) -> tuple[str, str]:
    """Create a stack from the S3-key template and wait for a terminal StackStatus. Returns
    (stack_name, status)."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("badkey-stack")
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "CodeBucket", "ParameterValue": bucket_name},
            {"ParameterKey": "CodeKey", "ParameterValue": code_key},
        ],
        Capabilities=["CAPABILITY_IAM"],
        Tags=_xsvc_tags_kv(),
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_id))
    status = _poll_until(
        probe=lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        predicate=lambda s: (
            s in ("CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_COMPLETE")
        ),
        timeout_s=timeout_s,
        interval_s=5,
        description=f"CFN stack {stack_name}",
    )
    return stack_name, status


def _assert_function_absent(ctx, fn_name: str) -> None:
    """Independent read at the Lambda destination: the function this stack would have created
    must not exist."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    expected = f"Function not found: arn:aws:lambda:{ctx.region}:{account}:function:{fn_name}"
    try:
        ctx.client("lambda").get_function(FunctionName=fn_name)
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"Expected ResourceNotFoundException reading {fn_name}, got: {e}"
        )
        message = e.response["Error"].get("Message")
        assert message == expected, f"GetFunction message {message!r} != {expected!r}"
        return
    raise AssertionError(
        f"Lambda function {fn_name} exists, but its stack never reached CREATE_COMPLETE"
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN Lambda whose Code.S3Key names a real object reaches CREATE_COMPLETE and the function
    is independently readable; the identical stack pointed at a non-existent key fails CREATE and
    the function never comes into existence."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")

    good_key = "code/good.zip"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", "def lambda_handler(event, context):\n    return event\n")
    s3.put_object(Bucket=bucket["name"], Key=good_key, Body=zip_buf.getvalue())

    # Positive control: proves the account, role and template are otherwise healthy, so the
    # negative below is attributable to the missing key specifically, not to every Lambda-backed
    # stack failing in this account.
    good_stack, good_status = _deploy_and_wait(
        ctx, _LAMBDA_S3_KEY_YAML_TEMPLATE, bucket["name"], good_key
    )
    assert good_status == "CREATE_COMPLETE", (
        f"Positive control: expected CREATE_COMPLETE for a real S3 key, got: {good_status}"
    )
    lam.get_function(FunctionName=_function_name_for_stack(good_stack))

    bad_stack, bad_status = _deploy_and_wait(
        ctx, _LAMBDA_S3_KEY_YAML_TEMPLATE, bucket["name"], "nonexistent/code.zip"
    )
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"Expected the stack to fail CREATE and roll back for a non-existent S3 key, got: {bad_status}"
    )
    failed = [
        e.get("ResourceStatusReason", "")
        for page in ctx.client("cloudformation").get_paginator("describe_stack_events").paginate(
            StackName=bad_stack)
        for e in page["StackEvents"]
        if e["LogicalResourceId"] == "LambdaFunction" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(failed) == 1 and _MISSING_KEY_REASON.fullmatch(failed[0]), (
        f"the LambdaFunction CREATE_FAILED reasons are {failed!r}, expected one matching "
        f"{_MISSING_KEY_REASON.pattern!r}"
    )
    _assert_function_absent(ctx, _function_name_for_stack(bad_stack))


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Empty every object version and delete marker, then delete the bucket."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":  # us-east-1 refuses an explicit LocationConstraint
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
