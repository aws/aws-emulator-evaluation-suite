"""deploy-lambda-3-update-missing-code-object-rolls-back."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-3-update-missing-code-object-rolls-back"

GROUP = "deploy-lambda-update-rollback"

SERVICES = ["cloudformation", "iam", "lambda", "s3", "ssm"]

_FN_LOGICAL_ID = "Fn"
_PARAM_LOGICAL_ID = "Param"


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An update whose Lambda Code.S3Key names a missing object rolls back every resource, reverting
    the already-applied SSM change, while the function keeps serving its old code; a repaired
    update with a valid key then deploys and runs the new code.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")

    bucket = ctx.unique_name("sim2real-xsvc-code-")
    stack_name = ctx.unique_name("sim2real-xsvc-stk-")
    fn_name = ctx.unique_name("sim2real-xsvc-fn-")
    param_name = "/" + ctx.unique_name("sim2real-xsvc-param-")
    key_v1 = "code/v1.zip"
    key_v2 = "code/v2.zip"
    key_missing = "code/does-not-exist.zip"

    create_kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    zip_v1 = _zip_handler("one")
    zip_v2 = _zip_handler("two")
    s3.put_object(Bucket=bucket, Key=key_v1, Body=zip_v1)
    s3.put_object(Bucket=bucket, Key=key_v2, Body=zip_v2)

    missing_code, _ = _error_code(lambda: s3.head_object(Bucket=bucket, Key=key_missing))
    assert missing_code == "404", (
        f"HeadObject on the never-written key {key_missing!r} returned {missing_code!r}, expected '404'"
    )

    # The log group is created on first invoke and NOT removed by DeleteFunction; registering its
    # reap before the stack exists makes LIFO run it after the stack delete.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{fn_name}"))

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(fn_name, param_name, bucket, key_v1, "v1")),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name, timeout_s=600.0))
    status = _wait_stack(cfn, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"})
    assert status == "CREATE_COMPLETE", f"initial deploy ended {status!r}: {_stack(cfn, stack_name).get('StackStatusReason')!r}"

    out = _invoke(lam, fn_name)
    assert out == "one", f"v1 function returned {out!r}, expected 'one'"

    sha_v1 = lam.get_function_configuration(FunctionName=fn_name)["CodeSha256"]
    assert sha_v1 == _code_sha(zip_v1), (
        f"deployed CodeSha256 {sha_v1!r} is not the base64 SHA-256 of the uploaded v1 zip {_code_sha(zip_v1)!r}"
    )
    before = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert before == "v1", f"SSM parameter deployed as {before!r}, expected 'v1'"

    seen = {e["EventId"] for e in _events(cfn, stack_name)}
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(fn_name, param_name, bucket, key_missing, "v2-must-revert")),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_xsvc_tags_kv(),
    )

    status = _wait_stack(cfn, stack_name, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"})
    stack = _stack(cfn, stack_name)
    new_events = [e for e in _events(cfn, stack_name) if e["EventId"] not in seen]
    new_events.reverse()  # chronological
    print("[observe] rollback stack:", json.dumps({k: stack.get(k) for k in ("StackStatus", "StackStatusReason")}))
    for e in new_events:
        print("[observe] event:", e["LogicalResourceId"], e["ResourceStatus"], repr(e.get("ResourceStatusReason")))
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"an update whose Code.S3Key names a missing object must roll back; stack ended {status!r} "
        f"({stack.get('StackStatusReason')!r})"
    )
    # Once UPDATE_ROLLBACK_COMPLETE, DescribeStacks' StackStatusReason is null; the failed logical id
    # is carried durably by the stack's UPDATE_ROLLBACK_IN_PROGRESS event.
    stack_id = stack["StackId"]
    rb_events = [
        e for e in new_events
        if e.get("PhysicalResourceId") == stack_id and e["ResourceStatus"] == "UPDATE_ROLLBACK_IN_PROGRESS"
    ]
    assert len(rb_events) == 1, (
        f"expected one stack-level UPDATE_ROLLBACK_IN_PROGRESS event, got "
        f"{[(e['LogicalResourceId'], e['ResourceStatus']) for e in new_events]!r}"
    )
    reason = rb_events[0].get("ResourceStatusReason") or ""
    assert _bracketed_ids(reason) == {_FN_LOGICAL_ID}, (
        f"the stack's rollback reason must name exactly the failed logical id {_FN_LOGICAL_ID!r}; got {reason!r}"
    )

    fn_failed = [e for e in new_events if e["LogicalResourceId"] == _FN_LOGICAL_ID and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert len(fn_failed) == 1, (
        f"expected exactly one UPDATE_FAILED event for {_FN_LOGICAL_ID!r}, got "
        f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in new_events if e['LogicalResourceId'] == _FN_LOGICAL_ID]!r}"
    )
    fn_reason = fn_failed[0].get("ResourceStatusReason") or ""
    assert "NoSuchKey" in fn_reason, (
        f"the Function's UPDATE_FAILED reason must surface S3's NoSuchKey for the missing object; got {fn_reason!r}"
    )

    # The SSM change was APPLIED before the Function failed (the Function DependsOn it), and
    # then reverted by the rollback: one UPDATE_COMPLETE before the failure, one after.
    fail_idx = new_events.index(fn_failed[0])
    param_done = [i for i, e in enumerate(new_events) if e["LogicalResourceId"] == _PARAM_LOGICAL_ID and e["ResourceStatus"] == "UPDATE_COMPLETE"]
    assert any(i < fail_idx for i in param_done) and any(i > fail_idx for i in param_done), (
        f"{_PARAM_LOGICAL_ID!r} must be updated before the Function fails and updated back during the "
        f"rollback; its UPDATE_COMPLETE events sit at {param_done!r}, Function failed at {fail_idx}"
    )

    after = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert after == before, (
        f"rollback must restore SSM parameter {param_name!r} to {before!r}; it reads {after!r}"
    )

    sha_after = lam.get_function_configuration(FunctionName=fn_name)["CodeSha256"]
    assert sha_after == sha_v1, f"CodeSha256 changed across a rolled-back update: {sha_v1!r} -> {sha_after!r}"
    out = _invoke(lam, fn_name)
    assert out == "one", f"after rollback the function returned {out!r}, expected the v1 'one'"

    # The CFN failure is Lambda's own rejection: the same missing key, sent straight to
    # UpdateFunctionCode, is refused with the exact code and changes nothing.
    direct, direct_message = _error_code(lambda: lam.update_function_code(FunctionName=fn_name, S3Bucket=bucket, S3Key=key_missing))
    assert direct == "InvalidParameterValueException", (
        f"UpdateFunctionCode with a missing S3 key returned {direct!r}, expected 'InvalidParameterValueException'"
    )
    expected_direct_message = "Error occurred while GetObject. S3 Error Code: NoSuchKey. S3 Error Message: The specified key does not exist."
    assert direct_message == expected_direct_message, f"message {direct_message!r} != {expected_direct_message!r}"
    sha_direct = lam.get_function_configuration(FunctionName=fn_name)["CodeSha256"]
    assert sha_direct == sha_v1, f"a rejected UpdateFunctionCode changed CodeSha256 {sha_v1!r} -> {sha_direct!r}"

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(fn_name, param_name, bucket, key_v2, "v2")),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_xsvc_tags_kv(),
    )
    status = _wait_stack(cfn, stack_name, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"})
    assert status == "UPDATE_COMPLETE", (
        f"the repaired update must succeed; stack ended {status!r} ({_stack(cfn, stack_name).get('StackStatusReason')!r})"
    )
    sha_v2 = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda c: c.get("LastUpdateStatus") == "Successful",
        timeout_s=120.0, interval_s=3.0, description="function code update settles",
    )["CodeSha256"]
    assert sha_v2 == _code_sha(zip_v2), (
        f"after the repair CodeSha256 is {sha_v2!r}, expected the v2 zip's {_code_sha(zip_v2)!r}"
    )
    out = _invoke(lam, fn_name)
    assert out == "two", f"after the repaired update the function returned {out!r}, expected 'two'"
    repaired = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert repaired == "v2", f"the repaired update must apply the SSM value 'v2'; it reads {repaired!r}"

    _delete_stack_and_wait(cfn, stack_name, timeout_s=600.0)
    gone, gone_message = _error_code(lambda: cfn.describe_stacks(StackName=stack_name))
    assert gone == "ValidationError", f"DescribeStacks on a deleted stack returned {gone!r}, expected 'ValidationError'"
    expected_gone_message = f"Stack with id {stack_name} does not exist"
    assert gone_message == expected_gone_message, f"message {gone_message!r} != {expected_gone_message!r}"
    fn_gone, fn_gone_message = _error_code(lambda: lam.get_function(FunctionName=fn_name))
    assert fn_gone == "ResourceNotFoundException", (
        f"GetFunction after stack delete returned {fn_gone!r}, expected 'ResourceNotFoundException'"
    )
    expected_fn_gone_message = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}"
    assert fn_gone_message == expected_fn_gone_message, f"message {fn_gone_message!r} != {expected_fn_gone_message!r}"
    param_gone, param_gone_message = _error_code(lambda: ssm.get_parameter(Name=param_name))
    assert param_gone == "ParameterNotFound", (
        f"GetParameter after stack delete returned {param_gone!r}, expected 'ParameterNotFound'"
    )
    expected_param_gone_message = ""
    assert param_gone_message == expected_param_gone_message, f"message {param_gone_message!r} != {expected_param_gone_message!r}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


class _Succeeded:
    """Returned by _error_code when the call did NOT raise; never equal to an error code."""

    def __repr__(self) -> str:
        return "<call unexpectedly succeeded>"


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _error_code(fn):
    """``(code, message)`` of the ClientError ``fn`` raises; a success yields a code nothing equals."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    return _Succeeded(), ""


def _zip_handler(value: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("index.py", date_time=(2020, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        zf.writestr(info, f"def handler(event, context):\n    return {value!r}\n")
    return buf.getvalue()


def _code_sha(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _template(fn_name: str, param_name: str, bucket: str, key: str, value: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "FnRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    },
                    "ManagedPolicyArns": [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"}],
                },
            },
            _PARAM_LOGICAL_ID: {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": param_name, "Type": "String", "Value": value},
            },
            _FN_LOGICAL_ID: {
                "Type": "AWS::Lambda::Function",
                # Ordering makes the SSM change land BEFORE the Function update fails, so the
                # rollback has an applied change to revert rather than a cancelled one.
                "DependsOn": [_PARAM_LOGICAL_ID],
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["FnRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"S3Bucket": bucket, "S3Key": key},
                },
            },
        },
    }


def _bracketed_ids(reason: str) -> set[str]:
    """Logical ids from 'The following resource(s) failed to update: [A, B].'"""
    if "[" not in reason or "]" not in reason:
        return set()
    inner = reason[reason.index("[") + 1 : reason.index("]")]
    return {part.strip() for part in inner.split(",") if part.strip()}


def _invoke(lam, fn_name: str):
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}")
    body = resp["Payload"].read().decode()
    assert not resp.get("FunctionError"), f"{fn_name} raised: {body}"
    return json.loads(body)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack(cfn, name: str) -> dict:
    return cfn.describe_stacks(StackName=name)["Stacks"][0]


def _wait_stack(cfn, name: str, terminal: set[str], timeout_s: float = 600.0) -> str:
    return _poll_until(
        lambda: _stack(cfn, name)["StackStatus"],
        lambda s: s in terminal,
        timeout_s=timeout_s, interval_s=5.0, description=f"stack {name} reaches one of {sorted(terminal)}",
    )


def _events(cfn, name: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        out.extend(page.get("StackEvents", []))
    return out


def _delete_stack_and_wait(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as err:
        if _stack_missing(err):
            return
        raise

    def _status():
        try:
            return _stack(cfn, name)["StackStatus"]
        except ClientError as err:
            if _stack_missing(err):
                return "GONE"
            raise

    status = _poll_until(_status, lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                         timeout_s=timeout_s, interval_s=2.0, description=f"delete stack {name}")
    if status == "DELETE_FAILED":
        raise RuntimeError(f"stack {name} ended DELETE_FAILED: {_stack(cfn, name).get('StackStatusReason')!r}")


def _stack_missing(err: ClientError) -> bool:
    return err.response["Error"]["Code"] == "ValidationError" and "does not exist" in str(err)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _reap_log_group(ctx, group: str) -> None:
    """Delete the function's log group, then watch for a late flush recreating it."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + 12.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(3.0)
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g["logGroupName"] == group for g in found):
            if time.monotonic() >= deadline:
                return
            continue
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present after bounded reap")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
