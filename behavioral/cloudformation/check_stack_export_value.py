"""stack-export-value."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-export-value"
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

def _wait_deleted(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack fully deletes; return the terminal signal.

    Once a stack is gone, DescribeStacks-by-name raises "does not exist" rather than
    reporting DELETE_COMPLETE — that refusal IS the terminal signal, not an unknown
    transient, so it is treated as DELETE_COMPLETE.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
            if last in _TERMINAL_STATES:
                return last
        except ClientError as e:
            if "does not exist" in str(e):
                return "DELETE_COMPLETE"
            raise
        time.sleep(2)
    raise AssertionError(f"stack {name} did not fully delete within {timeout_s}s (last={last!r})")

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

def _export_template(export_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"Exported": {"Value": "exported-value-sim2real",
                                 "Export": {"Name": export_name}}},
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Exported output values appear in ListExports, and the export disappears
    from that same independent read once the exporting stack is deleted."""
    cf = ctx.client("cloudformation")
    export_name = ctx.unique_name("sim2real-behav-export-")
    name = _create_and_wait(
        ctx, cf, _export_template(export_name),
        tags=[{"Key": "sim2real", "Value": "true"}],
    )
    exports = cf.list_exports()
    found = False
    for exp in exports.get("Exports", []):
        if exp["Name"] == export_name:
            assert exp["Value"] == "exported-value-sim2real", (
                f"expected exported value 'exported-value-sim2real', got {exp['Value']!r}"
            )
            found = True
            break
    assert found, f"Export {export_name} not found in ListExports"

    cf.delete_stack(StackName=name)
    status = _wait_deleted(cf, name)
    assert status == "DELETE_COMPLETE", f"Stack {name} ended in {status}, expected DELETE_COMPLETE"
    exports_after = cf.list_exports()
    assert not any(exp["Name"] == export_name for exp in exports_after.get("Exports", [])), (
        f"Export {export_name} still present in ListExports after stack {name} was deleted"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
