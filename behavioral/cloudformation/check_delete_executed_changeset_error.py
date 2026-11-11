"""delete-executed-changeset-error."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "delete-executed-changeset-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
        }
    }
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a change set that has already been executed is *allowed* (unlike re-executing
    it, which is rejected) -- DeleteChangeSet is a cleanup operation and real CloudFormation
    permits it on an already-applied change set, actually removing the change set record."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-dcs-")
    cs_name = ctx.unique_name("sim2real-behav-cs-")

    cs_id = cfn.create_change_set(
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

    # Real CloudFormation does NOT reject DeleteChangeSet
    # on an already-executed change set -- it succeeds and actually removes the change set.
    # Assert the call succeeds, then assert the deletion actually took effect: the change set
    # can no longer be described (it comes back as not-found), the same "ChangeSetNotFound"
    # awsQuery error code used elsewhere for missing change sets.
    cfn.delete_change_set(StackName=stack_name, ChangeSetName=cs_name)

    gone = _expect_error(
        lambda: cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
    )
    expected_gone = ("ChangeSetNotFound", f"ChangeSet [{cs_name}] does not exist")
    assert gone == expected_gone, (
        f"expected the change set to be gone after deletion {expected_gone!r}, got {gone!r}"
    )

    # A mutation on the now-dead id must fail too, not silently re-execute a change set that
    # no longer exists. Real CloudFormation is asymmetric here: name-based DescribeChangeSet
    # stops indexing an executed change set by name (ChangeSetNotFound, asserted above), but
    # name-based ExecuteChangeSet still resolves the underlying record and rejects it for its
    # (still-tracked) EXECUTE_COMPLETE status -- InvalidChangeSetStatus, not ChangeSetNotFound.
    executed = _expect_error(
        lambda: cfn.execute_change_set(StackName=stack_name, ChangeSetName=cs_name)
    )
    expected_exec = (
        "InvalidChangeSetStatus",
        f"ChangeSet [{cs_id}] cannot be executed in its current execution status of [EXECUTE_COMPLETE]",
    )
    assert executed == expected_exec, (
        f"ExecuteChangeSet on the deleted change set: expected {expected_exec!r}, got {executed!r}"
    )

    # The name is reusable once the old change set is gone: creating a fresh change set under
    # the identical name on the identical stack must succeed rather than colliding.
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        TemplateBody=_TEMPLATE,
        ChangeSetType="UPDATE",
    )
    ctx.on_cleanup(lambda: cfn.delete_change_set(StackName=stack_name, ChangeSetName=cs_name))


def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.
    Raises when fn() succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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
