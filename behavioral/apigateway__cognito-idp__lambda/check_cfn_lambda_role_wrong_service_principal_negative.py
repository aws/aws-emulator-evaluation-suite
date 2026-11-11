"""cfn-lambda-role-wrong-service-principal-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-lambda-role-wrong-service-principal-negative"
GROUP = "iam-trust"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting apigateway.amazonaws.com instead of lambda.amazonaws.com makes the stack's
    AWS::Lambda::Function fail to create, while an identical stack with the correct trust succeeds."""
    bad_function_name = ctx.unique_name("sim2real-wrongprincipal-fn-")
    bad_marker = ctx.unique_name("sim2real-wrongprincipal-")
    bad_name, status = _deploy_cfn_expect_failure(
        ctx, _template(bad_function_name, "apigateway.amazonaws.com", bad_marker)
    )
    assert status == "ROLLBACK_COMPLETE", f"expected the stack to roll back, got {status}"

    lam = ctx.client("lambda")
    code, message = _client_error(lambda: lam.get_function(FunctionName=bad_function_name))
    assert code == "ResourceNotFoundException", (
        f"the function must never have come into existence after the wrong-principal failure, got code={code}"
    )
    expected_message = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_function_name}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the identical template, changed only in the trust principal, deploys
    # cleanly and the function is invokable.
    good_function_name = ctx.unique_name("sim2real-rightprincipal-fn-")
    good_marker = ctx.unique_name("sim2real-rightprincipal-")
    _deploy_cfn(ctx, _template(good_function_name, "lambda.amazonaws.com", good_marker))
    resp = _poll_until(
        lambda: lam.invoke(FunctionName=good_function_name, Payload=b"{}"),
        lambda r: "FunctionError" not in r,
        timeout_s=60.0,
        interval_s=3.0,
        description="positive-control lambda invocation succeeds",
    )
    payload = json.loads(resp["Payload"].read())
    assert payload == {"marker": good_marker}, f"positive control did not execute correctly: {payload}"


def _template(function_name: str, principal: str, marker: str) -> str:
    """One template, varying only in the trust principal, so the wrong-principal stack and its
    positive control are otherwise identical -- the positive control proves this exact setup,
    fixed only in the one broken field, now succeeds."""
    code = "import os\n" "def handler(event, context):\n" "    return {'marker': os.environ.get('MARKER', '')}\n"
    template = {
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": code},
                    "Environment": {"Variables": {"MARKER": marker}},
                },
            },
        },
        "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
    }
    return json.dumps(template)


# ===== check-specific plumbing =====


def _client_error(fn):
    """Call fn, which AWS must refuse, and return the (code, message) of its ClientError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _deploy_cfn_expect_failure(ctx, template: str, stack_name: str | None = None) -> tuple[str, str]:
    """Like _deploy_cfn, but expects the stack to end in a FAILURE terminal state instead of
    asserting CREATE_COMPLETE. Still registers the delete-and-wait teardown."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=300.0,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    return name, status


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
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}),
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
