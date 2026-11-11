"""cross-stack-import-value."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-stack-import-value"
GROUP = 'stack_outputs'
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

def _delete_and_wait(cf, name, timeout_s=45):
    """DeleteStack and wait for DELETE_COMPLETE, so a dependent export/import isn't torn down early."""
    cf.delete_stack(StackName=name)
    status = _wait_terminal(cf, name, timeout_s=timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"Stack {name} failed to delete, ended in {status}")

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
    ctx.on_cleanup(lambda: _delete_and_wait(cf, name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name

def _export_template(export_name, export_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"Exported": {"Value": export_value,
                                 "Export": {"Name": export_name}}},
    })

def _import_template(export_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"Imported": {"Value": {"Fn::ImportValue": export_name}}},
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Fn::ImportValue resolves a value exported by another stack."""
    cf = ctx.client("cloudformation")
    export_name = ctx.unique_name("sim2real-behav-xref-")
    export_value = ctx.unique_name("sim2real-behav-xref-value-")
    stack_tags = [{"Key": "sim2real-check", "Value": CHECK}]
    _create_and_wait(ctx, cf, _export_template(export_name, export_value), tags=stack_tags)
    importer = _create_and_wait(ctx, cf, _import_template(export_name), tags=stack_tags)
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=importer)["Stacks"][0].get("Outputs", [])
    }
    assert outputs["Imported"] == export_value, (
        f"expected imported value {export_value!r}, got {outputs.get('Imported')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
