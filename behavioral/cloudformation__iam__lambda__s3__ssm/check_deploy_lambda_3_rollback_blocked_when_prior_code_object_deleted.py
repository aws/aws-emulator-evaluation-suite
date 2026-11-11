"""deploy-lambda-3-rollback-blocked-when-prior-code-object-deleted."""

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

CHECK = "deploy-lambda-3-rollback-blocked-when-prior-code-object-deleted"

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
    """CloudFormation's rollback of a Lambda Function RE-FETCHES the previous Code.S3Key from S3,
    so if that object has been deleted the rollback itself fails (UPDATE_ROLLBACK_FAILED), the
    stack refuses further updates, and ContinueUpdateRollback succeeds once the object is back.
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
    key_missing = "code/does-not-exist.zip"

    create_kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    zip_v1 = _zip_handler("one")
    s3.put_object(Bucket=bucket, Key=key_v1, Body=zip_v1)

    # Registered before the stack exists, so LIFO runs the log group reap after the stack
    # delete, and the bucket goes last.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{fn_name}"))

    # ---- deploy v1 ----
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
    assert sha_v1 == _code_sha(zip_v1), f"deployed CodeSha256 {sha_v1!r} is not the v1 zip's {_code_sha(zip_v1)!r}"

    # ---- break exactly one thing: the object the CURRENT code was deployed from ----
    s3.delete_object(Bucket=bucket, Key=key_v1)
    gone_code, _ = _error_code(lambda: s3.head_object(Bucket=bucket, Key=key_v1))
    assert gone_code == "404", f"HeadObject on the deleted v1 key returned {gone_code!r}, expected '404'"
    # The function itself does not depend on the object once deployed.
    out = _invoke(lam, fn_name)
    assert out == "one", f"deleting the source object changed what the function serves: {out!r}"

    # ---- a failing update (SSM change + missing key) whose rollback needs the deleted v1 ----
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
    print("[observe] stack:", json.dumps({k: stack.get(k) for k in ("StackStatus", "StackStatusReason")}))
    for e in new_events:
        print("[observe] event:", e["LogicalResourceId"], e["ResourceStatus"], repr(e.get("ResourceStatusReason"))[:200])
    assert status == "UPDATE_ROLLBACK_FAILED", (
        "rolling the Function back must re-fetch the deleted v1 object and fail; stack ended "
        f"{status!r} ({stack.get('StackStatusReason')!r})"
    )

    stack_id = stack["StackId"]
    rb_failed = [
        e for e in new_events
        if e.get("PhysicalResourceId") == stack_id and e["ResourceStatus"] == "UPDATE_ROLLBACK_FAILED"
    ]
    assert len(rb_failed) == 1, f"expected one stack-level UPDATE_ROLLBACK_FAILED event, got {len(rb_failed)}"
    rb_reason = rb_failed[0].get("ResourceStatusReason") or ""
    assert _bracketed_ids(rb_reason) == {_FN_LOGICAL_ID}, (
        f"the failed rollback must blame exactly {_FN_LOGICAL_ID!r}; got {rb_reason!r}"
    )

    # Two Function failures, both S3 NoSuchKey: the forward update (missing key) and the
    # rollback (deleted v1 key). The second one is what proves rollback re-reads S3.
    fn_failed = [e for e in new_events if e["LogicalResourceId"] == _FN_LOGICAL_ID and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert len(fn_failed) == 2, (
        f"expected the Function to fail twice (update, then rollback), got "
        f"{[(e['ResourceStatus'], (e.get('ResourceStatusReason') or '')[:80]) for e in new_events if e['LogicalResourceId'] == _FN_LOGICAL_ID]!r}"
    )
    for e in fn_failed:
        r = e.get("ResourceStatusReason") or ""
        assert "NoSuchKey" in r, f"a Function UPDATE_FAILED reason did not surface S3 NoSuchKey: {r!r}"
    rb_start = next(
        i for i, e in enumerate(new_events)
        if e.get("PhysicalResourceId") == stack_id and e["ResourceStatus"] == "UPDATE_ROLLBACK_IN_PROGRESS"
    )
    assert new_events.index(fn_failed[0]) < rb_start < new_events.index(fn_failed[1]), (
        "the second Function failure must happen DURING the rollback, after UPDATE_ROLLBACK_IN_PROGRESS"
    )

    # The sibling parameter's rollback still completed, and the function still serves v1.
    restored = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert restored == "v1", f"SSM parameter must be rolled back to 'v1' even though the stack rollback failed; reads {restored!r}"
    sha_now = lam.get_function_configuration(FunctionName=fn_name)["CodeSha256"]
    assert sha_now == sha_v1, f"CodeSha256 changed while the rollback failed: {sha_v1!r} -> {sha_now!r}"
    out = _invoke(lam, fn_name)
    assert out == "one", f"function returned {out!r} in UPDATE_ROLLBACK_FAILED, expected 'one'"

    # ---- a stack in UPDATE_ROLLBACK_FAILED refuses UpdateStack, and nothing changes ----
    refused, refused_message = _error_code(lambda: cfn.update_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(fn_name, param_name, bucket, key_v1, "v3")),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_xsvc_tags_kv(),
    ))
    assert refused == "ValidationError", f"UpdateStack in UPDATE_ROLLBACK_FAILED returned {refused!r}, expected 'ValidationError'"
    stack_id = _stack(cfn, stack_name)["StackId"]
    expected_refused_message = f"Stack:{stack_id} is in UPDATE_ROLLBACK_FAILED state and can not be updated."
    assert refused_message == expected_refused_message, f"message {refused_message!r} != {expected_refused_message!r}"
    still = _stack(cfn, stack_name)["StackStatus"]
    assert still == "UPDATE_ROLLBACK_FAILED", f"a refused UpdateStack moved the stack to {still!r}"
    unchanged = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert unchanged == "v1", f"a refused UpdateStack changed the SSM parameter to {unchanged!r}"

    # ---- control: put the v1 object back and the SAME rollback converges ----
    s3.put_object(Bucket=bucket, Key=key_v1, Body=zip_v1)
    cfn.continue_update_rollback(StackName=stack_name)
    status = _wait_stack(cfn, stack_name, {"UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"})
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"with the v1 object restored, ContinueUpdateRollback must converge; stack ended {status!r}"
    )
    sha_final = lam.get_function_configuration(FunctionName=fn_name)["CodeSha256"]
    assert sha_final == sha_v1, f"after the completed rollback CodeSha256 is {sha_final!r}, expected v1 {sha_v1!r}"
    out = _invoke(lam, fn_name)
    assert out == "one", f"after the completed rollback the function returned {out!r}, expected 'one'"

    # ---- delete; the stack and what it owned are gone ----
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
    """Delete the stack; a stack left in UPDATE_ROLLBACK_FAILED by a failed run is first
    rolled forward by skipping the Function, which DeleteStack would otherwise trip on."""
    try:
        if _stack(cfn, name)["StackStatus"] == "UPDATE_ROLLBACK_FAILED":
            cfn.continue_update_rollback(StackName=name, ResourcesToSkip=[_FN_LOGICAL_ID])
            _wait_stack(cfn, name, {"UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"}, timeout_s=timeout_s)
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
