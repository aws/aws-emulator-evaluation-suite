"""cfn-ssm-parameter-type-resolution-and-rule-assertion-negative."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-parameter-type-resolution-and-rule-assertion-negative"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "lambda", "ssm"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CloudFormation resolves an AWS::SSM::Parameter::Value<String> parameter by reading SSM, so
    the value reaches Outputs, ResolvedValue and the Lambda's environment; a Rules assertion that
    fails on the resolved value rolls the stack back with its AssertDescription, provisioning nothing."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    awslambda = ctx.client("lambda")

    template = (DEPLOYMENTS / "ssm-parameter-type-bootstrap-rule.yaml").read_text()

    good_param = "/" + _xname(ctx, "bootstrap-ok")
    bad_param = "/" + _xname(ctx, "bootstrap-old")
    for name, value in ((good_param, "21"), (bad_param, "3")):
        ssm.put_parameter(
            Name=name, Type="String", Value=value, Tags=_xsvc_tags_kv()
        )
        ctx.on_cleanup(lambda n=name: ssm.delete_parameter(Name=n))

    # ---- positive leg: the SSM value is resolved and reaches the deployed resource ----
    result = _deploy_cfn(
        ctx,
        template,
        parameters={"BootstrapVersion": good_param},
        capabilities=["CAPABILITY_IAM"],
        timeout_s=900.0,
    )
    stack_name = result["stack_name"]
    outputs = _outputs(result)

    assert outputs["ResolvedBootstrapVersion"] == "21", (
        "Ref of an AWS::SSM::Parameter::Value<String> parameter returned "
        f"{outputs['ResolvedBootstrapVersion']!r}; CloudFormation must substitute the SSM "
        f"VALUE ('21'), not the parameter name ({good_param!r})"
    )

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    declared = {p["ParameterKey"]: p for p in stack.get("Parameters", [])}
    assert declared["BootstrapVersion"]["ParameterValue"] == good_param, declared
    assert declared["BootstrapVersion"].get("ResolvedValue") == "21", (
        "DescribeStacks must report the SSM-resolved value in Parameters[].ResolvedValue, got "
        f"{declared['BootstrapVersion']}"
    )

    # The resolved value has to reach the provisioned Lambda, not just the stack metadata.
    payload = _invoke_json(awslambda, outputs["ReporterFunctionName"], {})
    assert payload.get("bootstrap_version") == "21", (
        f"deployed Lambda reports bootstrap_version={payload!r}; the resolved SSM value must be "
        "substituted into the resource properties CFN sends to Lambda"
    )

    # ---- negative leg: a failing Rules assertion must abort the deployment ----
    # CreateStack accepts the submission: Rules are evaluated once the SSM-typed parameter is
    # resolved, and the stack rolls back having provisioned nothing. The AssertDescription appears
    # in a stack event's ResourceStatusReason ("Parameter validation failed: assertion error: ...").
    rejected_stack = _xname(ctx, "stk-rules")
    cfn.create_stack(
        StackName=rejected_stack,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM"],
        Parameters=[{"ParameterKey": "BootstrapVersion", "ParameterValue": bad_param}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, rejected_stack, timeout_s=900.0))

    rejected_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=rejected_stack)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {
            "CREATE_COMPLETE",
            "CREATE_FAILED",
            "ROLLBACK_COMPLETE",
            "ROLLBACK_FAILED",
        },
        timeout_s=900.0,
        interval_s=5.0,
        description=f"stack {rejected_stack} reaches a terminal status",
    )
    assert rejected_status == "ROLLBACK_COMPLETE", (
        "a stack whose Rules assertion fails against the RESOLVED SSM value must roll back, "
        f"got {rejected_status!r}"
    )

    events = cfn.describe_stack_events(StackName=rejected_stack)["StackEvents"]
    reasons = [e.get("ResourceStatusReason") or "" for e in events]
    rule_reasons = [r for r in reasons if "Parameter validation failed" in r]
    assert rule_reasons, (
        "no stack event blames parameter validation; a Rules failure must be reported as "
        f"'Parameter validation failed: assertion error: ...'. Reasons seen: {reasons!r}"
    )
    assert any("bootstrap stack version 6 required" in r for r in rule_reasons), (
        "the failure must surface the template's AssertDescription so the operator can tell "
        f"WHICH rule failed; got {rule_reasons!r}"
    )

    # Effect absent: the rule fired BEFORE any resource was provisioned, and a rolled-back
    # stack publishes no Outputs.
    provisioned = [
        e["LogicalResourceId"]
        for e in events
        if e.get("ResourceType") not in (None, "AWS::CloudFormation::Stack")
    ]
    assert provisioned == [], (
        "a Rules failure must abort before any resource is created, but these resources have "
        f"events: {provisioned!r}"
    )
    rejected = cfn.describe_stacks(StackName=rejected_stack)["Stacks"][0]
    assert rejected.get("Outputs", []) == [], (
        f"a rolled-back stack must publish no Outputs, got {rejected.get('Outputs')!r}"
    )

    # The rule was evaluated against the RESOLVED value, not the parameter name: CFN reports
    # ResolvedValue '3' for the very submission it refused to deploy.
    rejected_params = {p["ParameterKey"]: p for p in rejected.get("Parameters", [])}
    assert rejected_params["BootstrapVersion"]["ParameterValue"] == bad_param, rejected_params
    assert rejected_params["BootstrapVersion"].get("ResolvedValue") == "3", (
        "the rejected stack must still report the SSM-resolved value that tripped the rule, "
        f"got {rejected_params['BootstrapVersion']}"
    )

    # Control: the rejection was about the VALUE, not the template or the parameter type.
    # The bad parameter itself is still a perfectly readable SSM parameter.
    control_value = ssm.get_parameter(Name=bad_param)["Parameter"]["Value"]
    assert control_value == "3", (
        f"bad_param {bad_param!r} should still be a readable SSM String parameter with value "
        f"'3' (the rejection was about the RESOLVED value tripping the Rule, not about SSM "
        f"itself), got {control_value!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


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


def _expect_client_error(fn, codes, description):
    """Require fn() to raise ClientError with an Error.Code in codes; return the code."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        assert code in codes, (
            f"{description}: expected error code in {sorted(codes)}, got {code!r} ({exc})"
        )
        return code
    raise AssertionError(f"{description}: call unexpectedly succeeded")


def _expect_client_error_response(fn, codes, description) -> dict:
    """As _expect_client_error, but returns the whole Error dict so the Message can be asserted."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = error.get("Code", "")
        assert code in codes, (
            f"{description}: expected error code in {sorted(codes)}, got {code!r} ({exc})"
        )
        return error
    raise AssertionError(f"{description}: call unexpectedly succeeded")


def _stack_names(cfn) -> set[str]:
    """Names of every stack that is not already deleted."""
    names: set[str] = set()
    token = None
    while True:
        kwargs: dict[str, Any] = {}
        if token:
            kwargs["NextToken"] = token
        page = cfn.list_stacks(**kwargs)
        for summary in page.get("StackSummaries", []):
            if summary.get("StackStatus") != "DELETE_COMPLETE":
                names.add(summary["StackName"])
        token = page.get("NextToken")
        if not token:
            return names


def _invoke_json(awslambda, function_name: str, payload: dict) -> dict:
    """Synchronously invoke a Lambda and decode its JSON result (asserting no function error)."""
    response = awslambda.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = response["Payload"].read().decode()
    assert not response.get("FunctionError"), f"{function_name} failed: {body}"
    return json.loads(body)


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown: a stack that does not go raises)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
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
    timeout_s=600.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
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
