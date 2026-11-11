"""e2e-workflow-cancellation-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-workflow-cancellation-flow"
GROUP = "e2e"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RequestCancelWorkflowExecution delivers a WorkflowExecutionCancelRequested
    decision event and, once the decider acts on it, the execution observably
    closes as CANCELED."""
    swf = ctx.client("swf")

    domain = _shared_domain(ctx)

    task_list = {"name": ctx.unique_name("sim2real-swf-tasklist-")}
    wf_type_name = ctx.unique_name("sim2real-swf-wftype-")
    swf.register_workflow_type(
        domain=domain,
        name=wf_type_name,
        version="1.0",
        defaultTaskStartToCloseTimeout="30",
        defaultExecutionStartToCloseTimeout="120",
        defaultTaskList=task_list,
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_type_name, "version": "1.0"}))

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    start_resp = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_type_name, "version": "1.0"},
        taskList=task_list,
    )
    run_id = start_resp["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}

    # Step 1: decider handles the initial decision task, leaving the workflow open
    # (no closing decisions -- just acknowledges the start).
    initial_task = _poll_for_decision_task(ctx, domain, task_list)
    assert initial_task.get("taskToken"), f"expected a decision task token, got {initial_task!r}"
    swf.respond_decision_task_completed(taskToken=initial_task["taskToken"], decisions=[])

    # Step 2: request cancellation -- this must record cancelRequested immediately,
    # without closing the execution by itself.
    swf.request_cancel_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id)
    described = swf.describe_workflow_execution(domain=domain, execution=execution)
    assert described["executionInfo"]["cancelRequested"] is True, (
        f"expected cancelRequested=True, got {described['executionInfo'].get('cancelRequested')!r}"
    )
    assert described["executionInfo"]["executionStatus"] == "OPEN", (
        f"expected executionStatus=OPEN, got {described['executionInfo']['executionStatus']!r}"
    )

    # Step 3: the resulting decision task must carry a WorkflowExecutionCancelRequested event.
    cancel_task = _poll_for_decision_task(ctx, domain, task_list)
    assert cancel_task.get("taskToken"), f"expected a decision task token, got {cancel_task!r}"
    event_types = [e["eventType"] for e in cancel_task["events"]]
    assert "WorkflowExecutionCancelRequested" in event_types, (
        f"expected WorkflowExecutionCancelRequested in {event_types!r}"
    )

    # Step 4: decider acts on it -- the execution must observably close as CANCELED.
    swf.respond_decision_task_completed(
        taskToken=cancel_task["taskToken"],
        decisions=[
            {
                "decisionType": "CancelWorkflowExecution",
                "cancelWorkflowExecutionDecisionAttributes": {"details": "user requested"},
            }
        ],
    )

    events = _poll_until_closed(ctx, domain, execution)
    described_final = swf.describe_workflow_execution(domain=domain, execution=execution)
    assert described_final["executionInfo"]["executionStatus"] == "CLOSED", (
        f"expected executionStatus=CLOSED, got {described_final['executionInfo']['executionStatus']!r}"
    )
    assert described_final["executionInfo"]["closeStatus"] == "CANCELED", (
        f"expected closeStatus=CANCELED, got {described_final['executionInfo'].get('closeStatus')!r}"
    )
    assert events[-1]["eventType"] == "WorkflowExecutionCanceled", (
        f"expected last history event WorkflowExecutionCanceled, got {events[-1]['eventType']!r}"
    )


def _poll_for_decision_task(ctx, domain, task_list, timeout_s=70.0):
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.poll_for_decision_task(domain=domain, taskList=task_list)
        if resp.get("taskToken"):
            return resp
    raise AssertionError("no decision task became available within timeout")


def _poll_until_closed(ctx, domain, execution, timeout_s=60.0, interval_s=2.0):
    swf = ctx.client("swf")
    terminal = {
        "WorkflowExecutionCompleted",
        "WorkflowExecutionFailed",
        "WorkflowExecutionCanceled",
        "WorkflowExecutionTerminated",
        "WorkflowExecutionTimedOut",
    }
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.get_workflow_execution_history(domain=domain, execution=execution)
        events = resp["events"]
        if events and events[-1]["eventType"] in terminal:
            return events
        time.sleep(interval_s)
    raise AssertionError("workflow execution did not close within timeout")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
