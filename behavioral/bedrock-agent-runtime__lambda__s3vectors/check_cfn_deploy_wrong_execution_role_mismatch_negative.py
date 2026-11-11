"""cfn-deploy-wrong-execution-role-mismatch-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-wrong-execution-role-mismatch-negative"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack Lambda whose execution role has no s3vectors or bedrock-agent-runtime permissions gets
    AccessDeniedException from both services, while an identical function on a permitted role in the
    same stack succeeds at both."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    good_fn_name = ctx.unique_name("sim2real-xsvc-goodfn-")
    good_role_name = ctx.unique_name("sim2real-xsvc-goodrole-")
    bad_fn_name = ctx.unique_name("sim2real-xsvc-badfn-")
    bad_role_name = ctx.unique_name("sim2real-xsvc-badrole-")
    template = _dual_role_template(good_fn_name, good_role_name, bad_fn_name, bad_role_name)
    stack = _deploy_cfn(ctx, template, teardown_deadline, timeout_s=180)
    good_function = stack["outputs"]["GoodFunctionName"]
    bad_function = stack["outputs"]["BadFunctionName"]

    good_result = _poll_until(
        lambda: _invoke_and_parse(ctx, good_function),
        lambda r: r["s3vectors"]["ok"] and r["bedrock"]["ok"],
        timeout_s=60,
        interval_s=5.0,
        description="positive-control role IAM permissions to become effective",
    )
    assert good_result["s3vectors"]["ok"] is True, good_result
    assert good_result["bedrock"]["ok"] is True, good_result

    bad_result = _invoke_and_parse(ctx, bad_function)
    assert bad_result["s3vectors"]["ok"] is False, bad_result
    assert bad_result["s3vectors"]["error_code"] == "AccessDeniedException", bad_result
    assert bad_result["bedrock"]["ok"] is False, bad_result
    assert bad_result["bedrock"]["error_code"] == "AccessDeniedException", bad_result


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"

_HANDLER_CODE = """import boto3


def handler(event, context):
    result = {}
    try:
        s3v = boto3.client("s3vectors")
        resp = s3v.list_vector_buckets()
        result["s3vectors"] = {"ok": True, "count": len(resp.get("vectorBuckets", []))}
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        result["s3vectors"] = {"ok": False, "error_code": code}
    try:
        bar = boto3.client("bedrock-agent-runtime")
        resp = bar.list_sessions()
        result["bedrock"] = {"ok": True, "count": len(resp.get("sessionSummaries", []))}
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        result["bedrock"] = {"ok": False, "error_code": code}
    return result
"""


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


#: The suite's cleanup budget; the stack teardowns of one run share one deadline inside it.
_CLEANUP_BUDGET_S = 900.0


def _delete_stack_and_wait(ctx, stack_name: str, teardown_deadline) -> None:
    """Delete the stack and poll every 2 s until it is gone, to the run's cleanup deadline;
    DELETE_FAILED raises at once."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_BUDGET_S)
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    while True:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ValidationError" and "does not exist" in error.get("Message", ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} still {status} at the cleanup deadline")
        time.sleep(2)


def _deploy_cfn(
    ctx,
    template,
    teardown_deadline,
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, teardown_deadline))
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


def _dual_role_template(
    good_function_name: str,
    good_role_name: str,
    bad_function_name: str,
    bad_role_name: str,
) -> str:
    logs_statement = {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "*",
    }
    statements_good = [
        logs_statement,
        {"Effect": "Allow", "Action": "s3vectors:ListVectorBuckets", "Resource": "*"},
        {"Effect": "Allow", "Action": "bedrock:ListSessions", "Resource": "*"},
    ]
    # The "mismatched" role: a role that exists and trusts lambda.amazonaws.com (so the function
    # deploys fine) but was wired up for an unrelated purpose and carries none of the data-plane
    # permissions this function's code actually needs.
    statements_bad = [logs_statement]

    def _role(name: str, statements: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": name,
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "Policies": [
                    {
                        "PolicyName": "policy",
                        "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
                    }
                ],
            },
        }

    def _fn(name: str, role_logical_id: str) -> dict[str, Any]:
        return {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": name,
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": [role_logical_id, "Arn"]},
                "Timeout": 15,
                "Code": {"ZipFile": _HANDLER_CODE},
            },
        }

    resources = {
        "GoodRole": _role(good_role_name, statements_good),
        "BadRole": _role(bad_role_name, statements_bad),
        "GoodFn": _fn(good_function_name, "GoodRole"),
        "BadFn": _fn(bad_function_name, "BadRole"),
    }
    outputs = {
        "GoodFunctionName": {"Value": {"Ref": "GoodFn"}},
        "BadFunctionName": {"Value": {"Ref": "BadFn"}},
    }
    return json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs}
    )


def _invoke_and_parse(ctx, function_name: str) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps({}).encode("utf-8"))
    payload = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation for {function_name} errored: {payload}")
    return payload


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
