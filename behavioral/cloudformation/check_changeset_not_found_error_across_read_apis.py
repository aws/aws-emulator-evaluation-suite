"""changeset-not-found-error-across-read-apis."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "changeset-not-found-error-across-read-apis"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A nonexistent change set ARN is refused with ChangeSetNotFound and "ChangeSet [<arn>] does not
    exist" by DescribeChangeSet, DescribeChangeSetHooks, GetTemplate and ExecuteChangeSet alike,
    while the same four calls succeed on a change set that exists."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    stack_name = ctx.unique_name("sim2real-behav-stk-cs404-")
    cs_name = f"cs-{uuid.uuid4().hex[:8]}"
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        ChangeSetType="CREATE",
        TemplateBody=_queue_template(ctx.unique_name("sim2real-behav-cs404-q-")),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ready = _wait_change_set_ready(cfn, cs_name, stack_name)
    assert ready["Status"] == "CREATE_COMPLETE", (
        f"positive control change set did not reach CREATE_COMPLETE: "
        f"{ready['Status']} ({ready.get('StatusReason')!r})"
    )
    cfn.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)
    cfn.describe_change_set_hooks(ChangeSetName=cs_name, StackName=stack_name)
    cfn.get_template(ChangeSetName=cs_name, StackName=stack_name)
    cfn.execute_change_set(ChangeSetName=cs_name, StackName=stack_name)
    status = _wait_terminal(cfn, stack_name)
    assert status == "CREATE_COMPLETE", (
        f"positive control stack did not reach CREATE_COMPLETE after execute: {status}"
    )

    arn = (
        f"arn:aws:cloudformation:{ctx.region}:{account}:changeSet/"
        f"sim2real-missing-changeset/{uuid.uuid4()}"
    )
    checks = [
        ("DescribeChangeSet", lambda: cfn.describe_change_set(ChangeSetName=arn)),
        ("DescribeChangeSetHooks", lambda: cfn.describe_change_set_hooks(ChangeSetName=arn)),
        ("GetTemplate", lambda: cfn.get_template(ChangeSetName=arn)),
        ("ExecuteChangeSet", lambda: cfn.execute_change_set(ChangeSetName=arn)),
    ]
    # Real CloudFormation sends the wire error code "ChangeSetNotFound" (no "Exception"
    # suffix) for this family, even though the modeled/documented shape name is
    # ChangeSetNotFoundException -- a well-known CFN Code/shape-name mismatch.
    for label, fn in checks:
        code, msg = _client_error(fn)
        assert code == "ChangeSetNotFound", (
            f"{label}(ChangeSetName=<nonexistent arn>): expected ChangeSetNotFound, "
            f"got {code!r}"
        )
        assert msg == f"ChangeSet [{arn}] does not exist", f"{label}: {msg!r}"


def _wait_terminal(cf, stack_name, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} terminal not met within {timeout_s}s (last={last!r})")


def _wait_change_set_ready(cf, cs_name, stack_name, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    resp = cf.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)
    while time.monotonic() < deadline:
        resp = cf.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)
        if resp["Status"] in ("CREATE_COMPLETE", "FAILED"):
            break
        time.sleep(2)
    return resp


def _queue_template(queue_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}},
        },
    })


def _client_error(fn):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


def _delete_stack(cfn, stack_name):
    """Teardown: delete the stack and wait for DELETE_COMPLETE; a failed delete raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
