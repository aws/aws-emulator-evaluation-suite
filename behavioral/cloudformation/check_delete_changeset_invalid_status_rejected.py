"""delete-changeset-invalid-status-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-changeset-invalid-status-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChangeSet on a change set still being created fails with InvalidChangeSetStatus and leaves it in
    place; once it reaches CREATE_COMPLETE the same delete succeeds and DescribeChangeSet fails with
    ChangeSetNotFound "ChangeSet [<name>] does not exist"."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-delcs-")
    cs_name = ctx.unique_name("sim2real-cs-")

    base_template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})
    # A template with many resources makes change-set creation (diffing) take long
    # enough to reliably still be CREATE_PENDING/CREATE_IN_PROGRESS immediately after
    # the CreateChangeSet call returns.
    updated_template = json.dumps(
        {
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic"},
                **{f"ExtraTopic{i}": {"Type": "AWS::SNS::Topic"} for i in range(40)},
            }
        }
    )

    ctx.on_cleanup(lambda: _swallow(lambda: cfn.delete_stack(StackName=stack_name)))

    cfn.create_stack(StackName=stack_name, TemplateBody=base_template)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        ChangeSetType="UPDATE",
        TemplateBody=updated_template,
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cfn.delete_change_set(StackName=stack_name, ChangeSetName=cs_name)))

    # Real CloudFormation sends the wire error code "InvalidChangeSetStatus" (no
    # "Exception" suffix) for this family, even though the modeled/documented shape
    # name is InvalidChangeSetStatusException -- same Code/shape-name mismatch as
    # ChangeSetNotFound(Exception). Try immediately, before the change set has had a
    # chance to leave its transient creating status.
    code, _message = _expect_error(lambda: cfn.delete_change_set(StackName=stack_name, ChangeSetName=cs_name))
    # message varies: it names the transient status the change set held at that instant
    # ("Cannot delete ChangeSet in status CREATE_PENDING" or ... CREATE_IN_PROGRESS).
    assert code == "InvalidChangeSetStatus", (
        f"deleting a change set that's still mid-creation: expected InvalidChangeSetStatus, got {code!r}"
    )

    # Effect-absent: the rejected delete must not have touched the change set -- an
    # independent read still finds it.
    still_there = _describe_change_set_tolerant(cfn, stack_name, cs_name, timeout_s=30)
    assert still_there.get("ChangeSetId"), (
        "change set should still exist after the rejected delete"
    )

    # Restore: the "invalid status" window is transient by construction (unlike an
    # always-invalid input) -- wait for it to clear on its own.
    final_status = _wait_for_change_set_status(
        cfn, stack_name, cs_name, {"CREATE_COMPLETE", "FAILED"}, timeout_s=180
    )
    assert final_status == "CREATE_COMPLETE", (
        f"change set never reached CREATE_COMPLETE: {final_status}"
    )

    # Restore leg: the identical delete call now succeeds against the same change set.
    cfn.delete_change_set(StackName=stack_name, ChangeSetName=cs_name)

    # Deletes prove gone: an independent read now reports the change set not-found.
    gone = _expect_error(lambda: cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name))
    expected_gone = ("ChangeSetNotFound", f"ChangeSet [{cs_name}] does not exist")
    assert gone == expected_gone, (
        f"expected the change set to be gone after deletion: {expected_gone!r}, got {gone!r}"
    )


def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.
    Raises when fn() succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _describe_change_set_tolerant(cfn, stack_name, cs_name, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("ChangeSetNotFoundException", "ChangeSetNotFound"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _wait_for_change_set_status(cfn, stack_name, cs_name, target_statuses, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _describe_change_set_tolerant(cfn, stack_name, cs_name, timeout_s=30)["Status"]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    return status


def _swallow(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ChangeSetNotFound",) or
            (exc.response["Error"]["Code"] == "ValidationError"
             and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
