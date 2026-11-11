"""duplicate-open-workflow-start-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "duplicate-open-workflow-start-rejected"
GROUP = "overly-permissive"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Starting a workflowId that has an OPEN execution fails with WorkflowExecutionAlreadyStartedFault (empty
    message) and leaves one OPEN execution; once it is closed, the same workflowId starts a new OPEN run."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)
    workflow_id = ctx.unique_name("sim2real-exec-")

    first = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType=wf_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout="300",
        taskStartToCloseTimeout="30",
        childPolicy="TERMINATE",
    )
    first_run_id = first["runId"]

    def _start_duplicate():
        swf.start_workflow_execution(
            domain=domain,
            workflowId=workflow_id,
            workflowType=wf_type,
            taskList={"name": task_list},
            executionStartToCloseTimeout="300",
            taskStartToCloseTimeout="30",
            childPolicy="TERMINATE",
        )

    code, message = _error(_start_duplicate)
    assert code == "WorkflowExecutionAlreadyStartedFault", f"unexpected error code: {code}"
    # AWS returns this fault with an empty message.
    assert message == "", f"expected an empty fault message, got {message!r}"

    # Effect absent: still exactly one OPEN execution for this workflowId, and it's the
    # original run (no new runId was created by the rejected duplicate start).
    open_count = swf.count_open_workflow_executions(
        domain=domain,
        startTimeFilter={"oldestDate": 0},
        executionFilter={"workflowId": workflow_id},
    )["count"]
    assert open_count == 1, f"expected exactly 1 open execution, found {open_count}"
    described = swf.describe_workflow_execution(
        domain=domain, execution={"workflowId": workflow_id, "runId": first_run_id}
    )
    status = described["executionInfo"]["executionStatus"]
    assert status == "OPEN", f"expected the original execution to still be OPEN, found {status}"

    # Positive control: closing the original execution then re-using the same workflowId
    # succeeds, proving the emulator isn't unconditionally rejecting StartWorkflowExecution.
    swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id)
    _poll_until_closed(swf, domain, {"workflowId": workflow_id, "runId": first_run_id})

    second = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType=wf_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout="300",
        taskStartToCloseTimeout="30",
        childPolicy="TERMINATE",
    )
    second_run_id = second["runId"]
    assert second_run_id and second_run_id != first_run_id, (
        f"expected a fresh runId distinct from {first_run_id}, got {second_run_id!r}"
    )
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, workflow_id))

    # Terminal read: an INDEPENDENT read at the destination, not the mutating call's own response.
    # Confirms the reused workflowId really seeded a new OPEN execution, not a fabricated runId.
    second_described = swf.describe_workflow_execution(
        domain=domain, execution={"workflowId": workflow_id, "runId": second_run_id}
    )
    second_status = second_described["executionInfo"]["executionStatus"]
    assert second_status == "OPEN", (
        f"expected the reused workflowId's new execution to be OPEN, found {second_status}"
    )
    reopened_count = swf.count_open_workflow_executions(
        domain=domain,
        startTimeFilter={"oldestDate": 0},
        executionFilter={"workflowId": workflow_id},
    )["count"]
    assert reopened_count == 1, (
        f"expected exactly 1 open execution after reuse, found {reopened_count}"
    )


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises. An unexpected success raises, so an
    emulator accepting a call AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


_SHARED_DOMAIN = "sim2real-swf-shared"


def _shared_domain(ctx) -> str:
    """The account's shared SWF domain, registered if absent and never deprecated: SWF has no
    DeleteDomain, and a deprecated domain counts toward the registered-domain quota."""
    swf = ctx.client("swf")
    try:
        status = swf.describe_domain(name=_SHARED_DOMAIN)["domainInfo"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise
        status = None
    try:
        if status is None:
            swf.register_domain(
                name=_SHARED_DOMAIN,
                workflowExecutionRetentionPeriodInDays="1",
                tags=[{"key": "sim2real:infra", "value": "swf-shared"}],
            )
        elif status == "DEPRECATED":
            swf.undeprecate_domain(name=_SHARED_DOMAIN)
    except ClientError as exc:
        # A concurrent run registered or restored it first.
        if exc.response["Error"]["Code"] != "DomainAlreadyExistsFault":
            raise
    return _SHARED_DOMAIN


def _delete_type(swf, domain: str, kind: str, type_ref: dict) -> None:
    """Teardown: deprecate then delete a workflow or activity type (``kind``), which the shared
    domain would otherwise keep; a type already deprecated or gone is fine."""
    arg = {"workflow": "workflowType", "activity": "activityType"}[kind]
    try:
        getattr(swf, f"deprecate_{kind}_type")(domain=domain, **{arg: type_ref})
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("TypeDeprecatedFault", "UnknownResourceFault"):
            raise
    try:
        getattr(swf, f"delete_{kind}_type")(domain=domain, **{arg: type_ref})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


def _register_workflow_type(ctx, domain: str, task_list: str) -> dict:
    swf = ctx.client("swf")
    name = ctx.unique_name("sim2real-wf-")
    version = "1.0"
    swf.register_workflow_type(
        domain=domain,
        name=name,
        version=version,
        defaultTaskStartToCloseTimeout="30",
        defaultExecutionStartToCloseTimeout="300",
        defaultTaskList={"name": task_list},
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": name, "version": version}))
    return {"name": name, "version": version}


def _poll_until_closed(swf, domain: str, execution: dict, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = swf.describe_workflow_execution(domain=domain, execution=execution)["executionInfo"]
        if info["executionStatus"] == "CLOSED":
            return
        time.sleep(1)
    raise AssertionError("execution never closed in time")


def _safe_terminate(ctx, domain: str, workflow_id: str) -> None:
    swf = ctx.client("swf")
    try:
        swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
