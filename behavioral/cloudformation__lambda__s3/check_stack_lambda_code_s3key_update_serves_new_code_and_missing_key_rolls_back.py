"""stack-lambda-code-s3key-update-serves-new-code-and-missing-key-rolls-back."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-lambda-code-s3key-update-serves-new-code-and-missing-key-rolls-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "s3"]

_HANDLER = "def handler(event, context):\n    return {{\"v\": \"{}\"}}\n"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Moving a function's Code.S3Key to a new object changes CodeSha256 to that object's digest
    and the invoke result; a key that does not exist fails the update, which rolls back with the
    previous code still serving.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfn-code-")
    function = ctx.unique_name("sim2real-cfn-code-")
    stack = ctx.unique_name("sim2real-cfn-code-")

    # us-east-1 is S3's default location and refuses a LocationConstraint naming itself.
    where = {} if ctx.region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    s3.create_bucket(Bucket=bucket, **where)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete(s3, bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    digests = {}
    for label in ("one", "two"):
        blob = _zip(_HANDLER.format(label))
        s3.put_object(Bucket=bucket, Key=f"{label}.zip", Body=blob)
        digests[label] = base64.b64encode(hashlib.sha256(blob).digest()).decode()

    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=_TEMPLATE, Capabilities=["CAPABILITY_IAM"],
        Parameters=_params(bucket, function, "one.zip"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    _expect_status(cfn, stack_id, "CREATE_COMPLETE")
    _expect_code(lam, function, digests["one"], "one")

    cfn.update_stack(StackName=stack_id, TemplateBody=_TEMPLATE, Capabilities=["CAPABILITY_IAM"],
                     Parameters=_params(bucket, function, "two.zip"))
    _expect_status(cfn, stack_id, "UPDATE_COMPLETE")
    _expect_code(lam, function, digests["two"], "two")

    cfn.update_stack(StackName=stack_id, TemplateBody=_TEMPLATE, Capabilities=["CAPABILITY_IAM"],
                     Parameters=_params(bucket, function, "missing.zip"))
    _expect_status(cfn, stack_id, "UPDATE_ROLLBACK_COMPLETE")
    failed = [e for e in _events(cfn, stack_id)
              if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Function", "UPDATE_FAILED")]
    assert len(failed) == 1, f"expected one UPDATE_FAILED event for the function, got {failed!r}"
    reason = failed[0].get("ResourceStatusReason") or ""
    assert re.fullmatch(
        r'Resource handler returned message: "Error occurred while GetObject\. S3 Error Code: '
        r'NoSuchKey\. S3 Error Message: The specified key does not exist\. \(Service: Lambda, '
        r'Status Code: 400, Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)" '
        r'\(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: InvalidRequest\)', reason), (
        f"the missing-key update failed with {reason!r}")
    _expect_code(lam, function, digests["two"], "two")

    # The same update with a key that exists succeeds from UPDATE_ROLLBACK_COMPLETE.
    cfn.update_stack(StackName=stack_id, TemplateBody=_TEMPLATE, Capabilities=["CAPABILITY_IAM"],
                     Parameters=_params(bucket, function, "one.zip"))
    _expect_status(cfn, stack_id, "UPDATE_COMPLETE")
    _expect_code(lam, function, digests["one"], "one")


_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"Bucket": {"Type": "String"}, "Key": {"Type": "String"},
                   "FunctionName": {"Type": "String"}},
    "Resources": {
        # No permissions at all: the handler logs nothing, so no log group is created.
        "Role": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}}},
        "Function": {"Type": "AWS::Lambda::Function", "Properties": {
            "FunctionName": {"Ref": "FunctionName"}, "Runtime": "python3.13",
            "Handler": "index.handler", "Role": {"Fn::GetAtt": ["Role", "Arn"]},
            "Code": {"S3Bucket": {"Ref": "Bucket"}, "S3Key": {"Ref": "Key"}}}},
    },
})


def _params(bucket: str, function: str, key: str) -> list[dict]:
    return [{"ParameterKey": "Bucket", "ParameterValue": bucket},
            {"ParameterKey": "Key", "ParameterValue": key},
            {"ParameterKey": "FunctionName", "ParameterValue": function}]


def _zip(source: str) -> bytes:
    """A deployment package holding index.py, with a fixed timestamp so its digest is stable."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("index.py", date_time=(2020, 1, 1, 0, 0, 0)), source)
    return out.getvalue()


def _expect_code(lam, function: str, digest: str, body: str) -> None:
    """The function's CodeSha256 is the package's digest and an invoke returns its body."""
    sha = lam.get_function(FunctionName=function)["Configuration"]["CodeSha256"]
    assert sha == digest, f"CodeSha256 is {sha!r}, expected the {body!r} package's {digest!r}"
    out = json.loads(lam.invoke(FunctionName=function)["Payload"].read())
    assert out == {"v": body}, f"the function returned {out!r}, expected {{'v': {body!r}}}"


def _expect_status(cfn, stack_id: str, want: str, *, timeout_s: float = 300.0) -> None:
    """Wait until no operation is in progress, then require ``want``."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3.0)
    assert stack["StackStatus"] == want, (
        f"stack ended {stack['StackStatus']!r}, expected {want!r} ({stack.get('StackStatusReason')!r})"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]][::-1]


def _empty_and_delete(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _delete_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} teardown ended {status!r}")
        time.sleep(5.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
