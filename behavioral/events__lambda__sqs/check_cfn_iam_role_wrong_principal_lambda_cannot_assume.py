"""cfn-iam-role-wrong-principal-lambda-cannot-assume."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-role-wrong-principal-lambda-cannot-assume"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sqs"]

_CODE = (
    "def handler(event, context):\n"
    "    return {'ok': True}\n"
)

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "GoodRoleName": {"Type": "String"},
        "BadRoleName": {"Type": "String"},
    },
    "Resources": {
        "GoodRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {"Ref": "GoodRoleName"},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "ManagedPolicyArns": [
                    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                ],
            },
        },
        "BadRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {"Ref": "BadRoleName"},
                # Wrong principal: trusts EC2, not Lambda. IAM accepts any syntactically valid
                # trust document at CreateRole time -- there is no validation the principal
                # will ever actually need this role.
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
            },
        },
    },
    "Outputs": {
        "GoodRoleArn": {"Value": {"Fn::GetAtt": ["GoodRole", "Arn"]}},
        "BadRoleArn": {"Value": {"Fn::GetAtt": ["BadRole", "Arn"]}},
    },
})


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction rejects a role that trusts ec2.amazonaws.com with the exact
    InvalidParameterValueException message and creates no function, while the correctly trusted
    role creates an invocable one."""
    lam = ctx.client("lambda")

    result = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "GoodRoleName": _xname(ctx, "good-role"),
            "BadRoleName": _xname(ctx, "bad-role"),
        },
    )
    good_role_arn = result["outputs"]["GoodRoleArn"]
    bad_role_arn = result["outputs"]["BadRoleArn"]

    # --- positive control: correctly-trusted role can be used to create + invoke a function ---
    good_fn_name = _xname(ctx, "good-fn")

    def _create_good():
        ctx.on_cleanup(lambda _n=good_fn_name: _delete_lambda_log_group(ctx, _n))
        return lam.create_function(
            FunctionName=good_fn_name,
            Runtime="python3.12",
            Handler="index.handler",
            Role=good_role_arn,
            Code={"ZipFile": _zip_bytes(_CODE)},
            Timeout=10,
            Tags=_xsvc_resource_tags(),
        )

    # IAM role propagation is eventually consistent immediately after CreateRole; retry
    # only on the specific "not yet assumable" transient error, and stop immediately on
    # success or any other error.
    deadline = time.monotonic() + 60.0
    created = False
    last_code: str | None = None
    while time.monotonic() < deadline and not created:
        try:
            _create_good()
            created = True
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code != "InvalidParameterValueException":
                raise
            time.sleep(3.0)
    assert created, f"create_function with correctly-trusted role never succeeded (last error: {last_code})"
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=good_fn_name)["State"],
        lambda s: s == "Active",
        timeout_s=90,
        interval_s=3.0,
        description=f"function {good_fn_name} Active",
    )
    invoke = lam.invoke(FunctionName=good_fn_name, InvocationType="RequestResponse")
    assert invoke.get("FunctionError") is None, (
        f"expected the correctly-trusted function to invoke cleanly, got FunctionError="
        f"{invoke.get('FunctionError')!r}"
    )
    payload = json.loads(invoke["Payload"].read())
    assert payload == {"ok": True}, f"expected {{'ok': True}}, got {payload!r}"

    # --- negative: wrong-trust role is rejected, function never created ---
    bad_fn_name = _xname(ctx, "bad-fn")

    def _cleanup_bad_fn():
        try:
            lam.delete_function(FunctionName=bad_fn_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_bad_fn)

    def _attempt_bad_create():
        ctx.on_cleanup(lambda _n=bad_fn_name: _delete_lambda_log_group(ctx, _n))
        return _error(
            lambda: lam.create_function(
                FunctionName=bad_fn_name,
                Runtime="python3.12",
                Handler="index.handler",
                Role=bad_role_arn,
                Code={"ZipFile": _zip_bytes(_CODE)},
                Timeout=10,
            )
        )

    # The wrong-trust role must stay rejected across the same window CreateRole propagation
    # needs to settle, not just on a single attempt taken on faith after a blind sleep: poll
    # repeatedly through that window and demand every attempt sees the identical rejection, so
    # a transient "not yet assumable" error can never be mistaken for -- or mask -- the real
    # trust rejection.
    poll_deadline = time.monotonic() + 10.0
    errors_seen: set[tuple[str, str]] = set()
    while True:
        errors_seen.add(_attempt_bad_create())
        if time.monotonic() >= poll_deadline:
            break
        time.sleep(2.0)
    expected_rejection = (
        "InvalidParameterValueException",
        "The role defined for the function cannot be assumed by Lambda.",
    )
    assert errors_seen == {expected_rejection}, (
        f"expected every attempt to create a function with the wrong-trust role to fail with "
        f"{expected_rejection!r}, saw {errors_seen!r}"
    )

    not_found_code, not_found_message = _error(lambda: lam.get_function(FunctionName=bad_fn_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected the never-created bad-trust function to be absent (ResourceNotFoundException), "
        f"got {not_found_code!r}"
    )
    expected_not_found = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn_name}"
    )
    assert not_found_message == expected_not_found, (
        f"expected GetFunction's not-found message {expected_not_found!r}, got {not_found_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); it must raise a ClientError. Returns the AWS error (Code, Message), or raises if
    fn unexpectedly succeeded."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _zip_bytes(code: str) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


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
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
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
    template_body = template.read_text() if hasattr(template, "read_text") else template
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
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
