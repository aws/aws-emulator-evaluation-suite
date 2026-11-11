"""delete-change-set."""
from __future__ import annotations

import json
import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-change-set"
GROUP = 'change_sets'
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

def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.

    Raises if fn() succeeds instead, naming the unexpected result.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })

def _two_handles_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Handle1": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Handle2": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        },
    })


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChangeSet removes it; subsequent Describe AND Execute against the
    freed name raise ChangeSetNotFoundException -- the identity must not be
    resurrectable or silently treated as a no-op."""
    cf = ctx.client("cloudformation")
    stack_name = _create_and_wait(
        ctx, cf, _handle_template(), tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    cs_name = f"cs-{uuid.uuid4().hex[:8]}"
    cf.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=_two_handles_template(),
    )
    deadline = time.monotonic() + 60
    status = None
    while time.monotonic() < deadline:
        resp = cf.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)
        status = resp["Status"]
        if status in ("CREATE_COMPLETE", "FAILED"):
            break
        time.sleep(2)
    else:
        raise AssertionError(
            f"change set {cs_name} did not reach CREATE_COMPLETE/FAILED within 60s "
            f"(last status={status!r})"
        )
    cf.delete_change_set(ChangeSetName=cs_name, StackName=stack_name)
    not_found = ("ChangeSetNotFound", f"ChangeSet [{cs_name}] does not exist")
    got = _expect_error(
        lambda: cf.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)
    )
    assert got == not_found, f"DescribeChangeSet: expected {not_found!r}, got {got!r}"
    exec_got = _expect_error(
        lambda: cf.execute_change_set(ChangeSetName=cs_name, StackName=stack_name)
    )
    assert exec_got == not_found, f"ExecuteChangeSet: expected {not_found!r}, got {exec_got!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
