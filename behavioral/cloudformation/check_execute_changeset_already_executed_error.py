"""execute-changeset-already-executed-error."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "execute-changeset-already-executed-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
        }
    }
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-executing an already-executed change set is rejected with InvalidChangeSetStatusException
    rather than silently re-applying it."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-xcs-")
    cs_name = ctx.unique_name("sim2real-behav-cs-")

    change_set_id = cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=_TEMPLATE,
        ChangeSetType="CREATE",
    )["Id"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    _wait_for_change_set_status(ctx, stack_name, cs_name, {"CREATE_COMPLETE"}, {"FAILED"})
    cfn.execute_change_set(StackName=stack_name, ChangeSetName=cs_name)
    _wait_for_stack_status(
        ctx,
        stack_name,
        {"CREATE_COMPLETE"},
        {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
    )

    err = _expect_error(
        lambda: cfn.execute_change_set(StackName=stack_name, ChangeSetName=cs_name)
    ).response["Error"]
    # Real CloudFormation reports this via the awsQuery error code "InvalidChangeSetStatus"
    # (no "Exception" suffix) -- same wire-code family quirk as ChangeSetNotFound.
    assert err["Code"] == "InvalidChangeSetStatus", f"expected InvalidChangeSetStatus, got {err['Code']}"
    expected_message = (
        f"ChangeSet [{change_set_id}] cannot be executed in its current execution status of "
        "[EXECUTE_COMPLETE]"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # The rejected re-execute must not have touched the stack: an independent read
    # (DescribeStacks, not the rejected ExecuteChangeSet's own response) confirms it.
    unchanged = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert unchanged == "CREATE_COMPLETE", f"stack must be untouched by the rejected re-execute, got {unchanged}"


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_for_change_set_status(ctx, stack_name, cs_name, terminal_ok, terminal_bad, timeout_s=120.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
        status = resp["Status"]
        if status in terminal_ok or status in terminal_bad:
            break
        time.sleep(interval_s)
    if status not in terminal_ok:
        raise AssertionError(f"change set did not reach {terminal_ok}, ended at {status}")


def _wait_for_stack_status(ctx, stack_name, terminal_ok, terminal_bad, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status in terminal_ok or status in terminal_bad:
            break
        time.sleep(interval_s)
    if status not in terminal_ok:
        raise AssertionError(f"stack did not reach {terminal_ok}, ended at {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
