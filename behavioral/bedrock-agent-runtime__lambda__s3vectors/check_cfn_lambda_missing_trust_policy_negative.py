"""cfn-lambda-missing-trust-policy-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-lambda-missing-trust-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]

_CODE = 'def handler(event, context):\n    return {"ok": True}\n'


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A stack whose Lambda role trusts ec2.amazonaws.com instead of lambda.amazonaws.com fails or rolls
    back, its function never exists (GetFunction: ResourceNotFoundException with the exact message),
    while the same stack with the Lambda trust principal deploys a function that returns {"ok": true}."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    bad_template = _role_function_template(role_principal="ec2.amazonaws.com")
    bad = _deploy_cfn_expect_failure(ctx, bad_template, teardown_deadline)
    assert bad["status"] in {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}, bad

    cfn = ctx.client("cloudformation")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resources = cfn.describe_stack_resources(StackName=bad["stack_name"])["StackResources"]
    fn_resources = [r for r in resources if r["ResourceType"] == "AWS::Lambda::Function"]
    assert fn_resources, "expected a Lambda::Function resource in the failed stack"
    for r in fn_resources:
        # message varies: ResourceStatusReason embeds per-call request ids and tokens.
        assert r["ResourceStatus"] != "CREATE_COMPLETE", r
        phys_id = r.get("PhysicalResourceId")
        assert phys_id, f"expected a PhysicalResourceId on the failed resource, got {r!r}"
        code, message = _error_code(
            lambda: ctx.client("lambda").get_function(FunctionName=phys_id)
        )
        assert code == "ResourceNotFoundException", code
        expected_message = (
            f"Function not found: arn:aws:lambda:{ctx.region}:{account_id}:function:{phys_id}"
        )
        assert message == expected_message, (
            f"expected {expected_message!r}, got {message!r}"
        )

    # Positive control, same file: correct trust principal deploys and IS invokable.
    good_template = _role_function_template(role_principal="lambda.amazonaws.com")
    good = _deploy_cfn(ctx, good_template, teardown_deadline)
    function_name = good["outputs"]["FunctionName"]
    _wait_function_active(ctx, function_name)
    payload = _invoke_json(ctx, function_name)
    assert payload == {"ok": True}, f"expected {{'ok': True}}, got {payload!r}"


def _role_function_template(*, role_principal: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": role_principal},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                        ],
                    },
                },
                "Fn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Timeout": 20,
                        "Code": {"ZipFile": _CODE},
                    },
                },
            },
            "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
        }
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED -- the function of the "
        "rolled-back stack exists"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


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


def _deploy_cfn_expect_failure(ctx, template: str, teardown_deadline) -> dict[str, Any]:
    """Like `_deploy_cfn`, but for templates expected to FAIL to create — polls to a terminal
    state without asserting success, and still registers stack-delete-and-wait cleanup."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = _xname(ctx, "stk")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, teardown_deadline))
    status = _poll_until(
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
        timeout_s=180.0,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    return {"stack_name": name, "stack_id": stack_id, "status": status}


def _wait_function_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    state = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"lambda {function_name} Active",
    )
    if state != "Active":
        raise AssertionError(f"function {function_name} ended in state {state}")


def _invoke_json(ctx, function_name: str, payload: dict | None = None) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    assert resp["StatusCode"] == 200, resp
    body = resp["Payload"].read()
    if "FunctionError" in resp:
        raise AssertionError(f"function error: {body!r}")
    return json.loads(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
