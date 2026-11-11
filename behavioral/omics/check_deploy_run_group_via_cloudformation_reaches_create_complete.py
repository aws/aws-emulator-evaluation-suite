"""deploy-run-group-via-cloudformation-reaches-create-complete."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-run-group-via-cloudformation-reaches-create-complete"
GROUP = "deploy"
SERVICES = ["omics"]

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Omics::RunGroup really provisions the underlying HealthOmics
    resource (describable via the omics API with the templated properties) and DeleteStack really
    tears it down (GetRunGroup 404s afterwards) — not just tracked-and-forgotten by CFN."""
    omics = ctx.client("omics")
    group_name = _xname(ctx, "rungroup")

    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Sim2RealRunGroup:
    Type: AWS::Omics::RunGroup
    Properties:
      Name: {group_name}
      MaxCpus: 5
      MaxDuration: 60
      MaxRuns: 2
Outputs:
  RunGroupId:
    Value: !GetAtt Sim2RealRunGroup.Id
  RunGroupArn:
    Value: !GetAtt Sim2RealRunGroup.Arn
"""

    deployed = _deploy_cfn(ctx, template, capabilities=[], timeout_s=180.0)
    run_group_id = deployed["outputs"]["RunGroupId"]

    described = omics.get_run_group(id=run_group_id)
    assert described["name"] == group_name, f"expected name {group_name!r}, got {described['name']!r}"
    assert described["maxCpus"] == 5, f"expected maxCpus 5, got {described['maxCpus']!r}"
    assert described["maxDuration"] == 60, f"expected maxDuration 60, got {described['maxDuration']!r}"
    assert described["maxRuns"] == 2, f"expected maxRuns 2, got {described['maxRuns']!r}"

    stack_name = deployed["stack_name"]
    _delete_stack_and_wait(ctx, stack_name)

    code, message = _client_error(lambda: omics.get_run_group(id=run_group_id))
    assert code == "ResourceNotFoundException", (
        f"run group {run_group_id} is still describable after its CFN stack was deleted (got {code!r})"
    )
    expected = f"Run group {run_group_id} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====
def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE or the stack to be gone; other errors raise."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
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
        "Capabilities": capabilities if capabilities is not None else ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

