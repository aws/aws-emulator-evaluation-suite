"""stack-update-replaces-resource."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-update-replaces-resource"
GROUP = 'e2e_workflows'
SERVICES = ['cloudformation']


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return the name."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template}
    if parameters:
        kwargs["Parameters"] = parameters
    if tags:
        kwargs["Tags"] = tags
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cf.create_stack(**kwargs)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name

def _param_template(param_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": param_name, "Type": "String", "Value": "sim2real-v1"},
            },
        },
    })


def _param_exists(ssm, name):
    """True iff the SSM parameter exists (ParameterNotFound => False)."""
    try:
        ssm.get_parameter(Name=name)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ParameterNotFound":
            return False
        raise


def _delete_param_quietly(ssm, name):
    """Best-effort teardown for a physical resource that outlived the stack update."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """UpdateStack changing an immutable property (SSM Parameter Name) replaces
    the resource: the new physical id is live, the old physical id is gone under
    the default UpdateReplacePolicy, and the stack tracks the replacement."""
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    param_v1 = "/" + ctx.unique_name("sim2real-behav-replace-v1-")
    param_v2 = "/" + ctx.unique_name("sim2real-behav-replace-v2-")
    ctx.on_cleanup(lambda: _delete_param_quietly(ssm, param_v1))
    ctx.on_cleanup(lambda: _delete_param_quietly(ssm, param_v2))

    name = _create_and_wait(ctx, cf, _param_template(param_v1))
    assert _param_exists(ssm, param_v1), "setup did not provision the parameter"

    cf.update_stack(StackName=name, TemplateBody=_param_template(param_v2))
    status = _wait_terminal(cf, name)
    assert status == "UPDATE_COMPLETE", f"Expected UPDATE_COMPLETE, got {status}"

    physical = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cf.list_stack_resources(StackName=name)["StackResourceSummaries"]
    }
    assert physical.get("Param") in (param_v2, param_v2.lstrip("/")), (
        f"the stack must track the replacement resource {param_v2!r}, got "
        f"{physical.get('Param')!r}"
    )
    assert _param_exists(ssm, param_v2), "the replacement resource must exist after the update"
    assert not _param_exists(ssm, param_v1), (
        f"UpdateStack must delete the replaced resource {param_v1} under the default "
        "UpdateReplacePolicy (Delete); it survived"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
