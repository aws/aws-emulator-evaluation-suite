"""cfn-macro-transform-injects-working-resource."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-macro-transform-injects-working-resource"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "lambda", "ssm"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A registered macro runs during stack creation: the SSM parameter its fragment injects exists
    in SSM with the transform's value, its Output is published, and only the processed template
    (not the original) shows the expansion."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    macro_name = _xname(ctx, "macro").replace("-", "")  # macro names allow only [A-Za-z0-9]
    param_name = "/" + _xname(ctx, "macro-param")
    param_value = "injected-by-macro-" + macro_name[-8:]

    registration = _deploy_cfn(
        ctx,
        (DEPLOYMENTS / "macro-registration.yaml").read_text(),
        parameters={"MacroName": macro_name},
        capabilities=["CAPABILITY_IAM"],
        timeout_s=900.0,
    )
    assert _outputs(registration)["MacroName"] == macro_name, _outputs(registration)

    consumer_body = (
        (DEPLOYMENTS / "macro-consumer.yaml")
        .read_text()
        .replace("SIM2REAL_MACRO_NAME", macro_name)
        .replace("SIM2REAL_PARAM_NAME", param_name)
        .replace("SIM2REAL_PARAM_VALUE", param_value)
    )
    # Registered BEFORE the stack deploys (and so, LIFO, run AFTER the stack's own
    # delete-and-wait teardown below): this is a backstop for a stack delete that fails to
    # remove the parameter, not a race against it. Registering it after would delete the
    # parameter out from under the stack's own teardown and could leave the stack itself
    # stuck DELETE_FAILED.
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))
    consumer = _deploy_cfn(
        ctx,
        consumer_body,
        capabilities=["CAPABILITY_AUTO_EXPAND"],
        timeout_s=900.0,
    )
    consumer_stack = consumer["stack_name"]

    # 1. The injected resource exists in the stack, typed as the macro declared it.
    resources = {
        r["LogicalResourceId"]: r
        for r in cfn.list_stack_resources(StackName=consumer_stack)[
            "StackResourceSummaries"
        ]
    }
    assert "MacroInjectedParameter" in resources, (
        "macro-injected resource missing from the stack; only "
        f"{sorted(resources)} were created, so the macro was never applied"
    )
    assert resources["MacroInjectedParameter"]["ResourceType"] == "AWS::SSM::Parameter", (
        resources["MacroInjectedParameter"]
    )

    # 2. The injected resource is real and holds the transform-parameter value: the
    #    cross-service half. Cleanup backstop for this is registered above, before the
    #    stack deploys.
    stored = ssm.get_parameter(Name=param_name)["Parameter"]
    assert stored["Value"] == param_value, (
        f"SSM parameter injected by the macro holds {stored['Value']!r}, expected "
        f"{param_value!r} (the transform Parameters must reach the macro as event['params'])"
    )
    assert stored["Type"] == "String", stored

    # 3. The macro also injected an Output, which means CFN adopted the WHOLE returned
    #    fragment, not just its Resources section.
    outputs = _outputs(consumer)
    assert outputs.get("MacroInjectedParameterName") == param_name, (
        f"macro-injected Output missing/incorrect: {outputs}"
    )
    assert outputs.get("AnchorRef"), (
        f"the consumer's own declared Output disappeared during expansion: {outputs}"
    )

    # 4. The processed template must show the expansion; the original must not.
    processed = _template_text(cfn, consumer_stack, "Processed")
    assert "MacroInjectedParameter" in processed, (
        "GetTemplate(TemplateStage=Processed) does not contain the macro-injected resource"
    )
    original = _template_text(cfn, consumer_stack, "Original")
    assert "MacroInjectedParameter" not in original, (
        "GetTemplate(TemplateStage=Original) leaked the expansion; Original must be the "
        "body as submitted"
    )
    assert "SIM2REAL_MACRO_NAME" not in original, original[:400]


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


def _template_text(cfn, stack_name: str, stage: str) -> str:
    """GetTemplate as text; botocore hands back a dict for a JSON body and a str for YAML."""
    body = cfn.get_template(StackName=stack_name, TemplateStage=stage)["TemplateBody"]
    return body if isinstance(body, str) else json.dumps(body)


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
