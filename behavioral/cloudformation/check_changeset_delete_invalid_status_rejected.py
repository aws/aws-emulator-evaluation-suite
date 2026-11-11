"""changeset-delete-invalid-status-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "changeset-delete-invalid-status-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE_V1 = json.dumps(
    {"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "v1"}}}}
)
# A second, never-executed UPDATE change set on the same stack -- the positive control. It must
# stay deletable throughout, showing that the eventual rejection below is specific to a change set
# that has been executed, not DeleteChangeSet being broken for this stack in general.
_TEMPLATE_CONTROL = json.dumps(
    {"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "control"}}}}
)
# v2 adds a CreationPolicy-signaled WaitCondition alongside the trivial SNS property change. A bare
# property update on an SNS topic completes so fast that, on real AWS, the stack can reach
# UPDATE_COMPLETE before the test's immediate follow-up DeleteChangeSet call lands -- making the
# delete succeed instead of being rejected. The WaitCondition holds the stack (and therefore the
# change set's ExecutionStatus) in EXECUTE_IN_PROGRESS until the check calls SignalResource on it --
# a bounded window under the check's own control, not a fixed sleep, and (unlike a Handle-based
# WaitCondition, which needs a raw HTTP PUT to a presigned URL) restorable in-check via one API call.
_TEMPLATE_V2 = json.dumps(
    {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "v2"}},
            "Waiter": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "CreationPolicy": {"ResourceSignal": {"Timeout": "PT3M", "Count": 1}},
            },
        }
    }
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChangeSet of an executed UPDATE change set is refused with InvalidChangeSetStatus and
    "Cannot delete ChangeSet in execution status <status>" both during and after execution, and the
    change set stays; a never-executed change set on the same stack deletes cleanly."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-delinvalid-")
    cs_name = ctx.unique_name("sim2real-cs-")
    control_name = ctx.unique_name("sim2real-cs-control-")
    ctx.on_cleanup(lambda: _cleanup(cfn, stack_name, cs_name, control_name))

    cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE_V1)
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    control_resp = cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=control_name,
        ChangeSetType="UPDATE",
        TemplateBody=_TEMPLATE_CONTROL,
    )
    control_id = control_resp["Id"]
    control_status = _wait_change_set_status(
        cfn, control_id, stack_name, {"CREATE_COMPLETE", "FAILED"}, timeout_s=60
    )
    assert control_status == "CREATE_COMPLETE", (
        f"control change set never reached CREATE_COMPLETE: {control_status}"
    )
    # A never-executed change set is deletable: a ClientError here fails the check.
    cfn.delete_change_set(ChangeSetName=control_id, StackName=stack_name)
    control_gone_code, control_gone_msg = _client_error(
        lambda: cfn.describe_change_set(ChangeSetName=control_id, StackName=stack_name),
        "DescribeChangeSet of the deleted control change set",
    )
    assert control_gone_code == "ChangeSetNotFound", (
        f"expected the deleted control change set to be gone (ChangeSetNotFound), got {control_gone_code}"
    )
    assert control_gone_msg == f"ChangeSet [{control_id}] does not exist", control_gone_msg

    create_cs_resp = cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        ChangeSetType="UPDATE",
        TemplateBody=_TEMPLATE_V2,
    )
    # Use the change set's ARN (Id), not its bare name, for every describe/execute/delete call from
    # here on. Real AWS resolves DescribeChangeSet(ChangeSetName=<bare name>, StackName=...) through a
    # "pending change sets for this stack" index that stops indexing the change set by name as soon as
    # ExecuteChangeSet is called (the change set is no longer "pending" -- it's being applied), so a
    # name-based lookup can spuriously raise ChangeSetNotFoundException while the stack (and the change
    # set's own ExecutionStatus) is still genuinely EXECUTE_IN_PROGRESS. The ARN is a stable primary key
    # that remains resolvable throughout execution.
    cs_id = create_cs_resp["Id"]
    cs_status = _wait_change_set_status(
        cfn, cs_id, stack_name, {"CREATE_COMPLETE", "FAILED"}, timeout_s=120
    )
    assert cs_status == "CREATE_COMPLETE", f"change set never reached CREATE_COMPLETE: {cs_status}"

    cfn.execute_change_set(ChangeSetName=cs_id, StackName=stack_name)

    # ExecuteChangeSet is async: the change set's ExecutionStatus (and the stack's status) doesn't
    # flip to the in-progress state instantaneously. Poll (bounded) until the change set actually
    # reports EXECUTE_IN_PROGRESS -- only then is DeleteChangeSet guaranteed to observe the
    # in-progress status and reject the delete. Without this, an immediate delete call can race
    # ahead of CloudFormation's own state transition and land while the change set is still (from
    # the API's point of view) idle, letting the delete succeed instead of being rejected.
    exec_status = _wait_change_set_execution_status(
        cfn, cs_id, stack_name, {"EXECUTE_IN_PROGRESS"}, timeout_s=60
    )
    assert exec_status == "EXECUTE_IN_PROGRESS", (
        f"change set never reached EXECUTE_IN_PROGRESS: {exec_status}"
    )

    code, msg = _client_error(
        lambda: cfn.delete_change_set(ChangeSetName=cs_id, StackName=stack_name),
        "DeleteChangeSet of an executing change set",
    )
    # Real AWS returns the wire error code "InvalidChangeSetStatus" (no "Exception" suffix) --
    # distinct from the modeled botocore exception class name InvalidChangeSetStatusException.
    assert code == "InvalidChangeSetStatus", (
        f"expected InvalidChangeSetStatus, got {code}"
    )
    assert msg == "Cannot delete ChangeSet in execution status EXECUTE_IN_PROGRESS", msg

    # The rejected delete must not have taken effect: an independent read (DescribeChangeSet, not
    # the mutating DeleteChangeSet call itself) must still resolve the change set.
    still_there = cfn.describe_change_set(ChangeSetName=cs_id, StackName=stack_name)
    assert still_there["ChangeSetId"] == cs_id, (
        f"change set should still exist after the rejected delete, describe returned {still_there!r}"
    )

    # Let the same update finish (the WaitCondition is signaled in-check) and re-check the delete
    # once ExecutionStatus is EXECUTE_COMPLETE: for an UPDATE change set, DeleteChangeSet refuses
    # once execution has started, not only while it is EXECUTE_IN_PROGRESS.
    #
    # SignalResource rejects a resource CloudFormation hasn't started creating yet ("Resource Waiter
    # does not exist for stack"), so wait for the Waiter's own resource status to show up before
    # signaling it.
    _wait_resource_in_progress(cfn, stack_name, "Waiter", timeout_s=60)

    cfn.signal_resource(
        StackName=stack_name,
        LogicalResourceId="Waiter",
        UniqueId="sim2real-delcs-signal-1",
        Status="SUCCESS",
    )
    final_stack_status = _wait_stack_status(cfn, stack_name, {"UPDATE_COMPLETE"}, timeout_s=120)
    assert final_stack_status == "UPDATE_COMPLETE", (
        f"expected the signaled update to complete, got {final_stack_status}"
    )

    final_exec_status = _wait_change_set_execution_status(
        cfn, cs_id, stack_name, {"EXECUTE_COMPLETE"}, timeout_s=60
    )
    assert final_exec_status == "EXECUTE_COMPLETE", (
        f"expected the change set's execution to complete, got {final_exec_status}"
    )

    final_code, final_msg = _client_error(
        lambda: cfn.delete_change_set(ChangeSetName=cs_id, StackName=stack_name),
        "DeleteChangeSet of an executed change set",
    )
    assert final_code == "InvalidChangeSetStatus", (
        f"expected DeleteChangeSet to remain rejected once the change set has executed "
        f"(ExecutionStatus={final_exec_status}), got {final_code}"
    )
    assert final_msg == "Cannot delete ChangeSet in execution status EXECUTE_COMPLETE", final_msg

    # The still-rejected delete must still not have taken effect.
    still_there_after = cfn.describe_change_set(ChangeSetName=cs_id, StackName=stack_name)
    assert still_there_after["ChangeSetId"] == cs_id, (
        f"executed change set should still exist after the rejected delete, "
        f"describe returned {still_there_after!r}"
    )


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")

def _wait_stack_status(cfn, stack_name, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in target_statuses or not status.endswith("IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    return status


def _describe_change_set_tolerant(cfn, cs_name, stack_name, deadline, interval_s):
    """describe_change_set, tolerating the transient ChangeSetNotFound that real AWS can return
    for a few moments right after CreateChangeSet -- the change set exists (CreateChangeSet
    already returned its Id) but hasn't yet propagated to the metadata store backing
    DescribeChangeSet. Retry (bounded by the caller's deadline) instead of letting this eventual
    consistency hiccup crash the check.
    """
    from botocore.exceptions import ClientError

    while True:
        try:
            return cfn.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("ChangeSetNotFoundException", "ChangeSetNotFound"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_change_set_status(cfn, cs_name, stack_name, target_statuses, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _describe_change_set_tolerant(cfn, cs_name, stack_name, deadline, interval_s)["Status"]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    return status


def _wait_change_set_execution_status(
    cfn, cs_name, stack_name, target_statuses, timeout_s=60.0, interval_s=0.5
):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _describe_change_set_tolerant(cfn, cs_name, stack_name, deadline, interval_s)[
            "ExecutionStatus"
        ]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    return status


def _wait_resource_in_progress(cfn, stack_name, logical_id, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stack_resource(
                StackName=stack_name, LogicalResourceId=logical_id
            )["StackResourceDetail"]["ResourceStatus"]
        except Exception:
            status = None
        if status is not None:
            return status
        time.sleep(interval_s)
    return status


def _cleanup(cfn, stack_name, cs_name, control_name):
    _wait_stack_status(
        cfn, stack_name, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}, timeout_s=180
    )
    # The executed change set is permanently undeletable via DeleteChangeSet (that is the contract
    # under test) -- deleting the stack removes it regardless.
    try:
        cfn.delete_change_set(ChangeSetName=cs_name, StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ChangeSetNotFound",) or
            (exc.response["Error"]["Code"] == "ValidationError"
             and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise
    try:
        cfn.delete_change_set(ChangeSetName=control_name, StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ChangeSetNotFound",) or
            (exc.response["Error"]["Code"] == "ValidationError"
             and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
