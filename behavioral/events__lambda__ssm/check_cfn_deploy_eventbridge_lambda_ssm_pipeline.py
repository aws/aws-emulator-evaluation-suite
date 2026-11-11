"""cfn-deploy-eventbridge-lambda-ssm-pipeline."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-lambda-ssm-pipeline"

GROUP = "deployment-order"

SERVICES = ["events", "lambda", "ssm"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation stack wires a rule, a Lambda and its invoke permission so that at
    CREATE_COMPLETE a matching event makes the function overwrite the SSM parameter with
    written-by-cfn-lambda."""
    template_path = (
        Path(__file__).parent / "deployments" / "eb-lambda-ssm-cfn" / "template.yaml"
    )
    assert template_path.is_file(), f"missing CFN fixture: {template_path}"

    suffix = uuid.uuid4().hex[:8]
    param_name = f"/sim2real-xsvc-cfn-{suffix}"
    event_source = f"integration.cfn-{suffix}"

    result = _deploy_cfn(
        ctx,
        template_path,
        parameters={
            "ParameterName": param_name,
            "EventSourceName": event_source,
        },
    )
    outputs = result["outputs"]
    assert outputs.get("ParameterName") == param_name, (
        f"unexpected stack outputs: {outputs}"
    )
    assert outputs.get("RuleArn", "").startswith("arn:aws:events:"), (
        f"bad RuleArn: {outputs}"
    )
    assert outputs.get("FunctionArn", "").startswith("arn:aws:lambda:"), (
        f"bad FunctionArn: {outputs}"
    )

    ssm = ctx.client("ssm")
    initial_value = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert initial_value == "initial", (
        f"expected CFN-deployed SSM parameter {param_name!r} to start at 'initial', "
        f"got {initial_value!r}"
    )

    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": event_source,
                "DetailType": "CfnTrigger",
                "Detail": json.dumps({}),
            }
        ]
    )

    def probe():
        try:
            return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
        except Exception:
            return None

    value = _wait_for_effect(
        probe, lambda v: v == "written-by-cfn-lambda", timeout_s=120
    )
    assert value == "written-by-cfn-lambda", (
        "CFN-deployed EventBridge rule did not invoke the CFN-deployed Lambda"
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


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE; a failure or timeout raises."""
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


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
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
