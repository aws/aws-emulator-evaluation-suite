"""e2e-workflow-execution-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-workflow-execution-lifecycle"
GROUP = "e2e"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full register->start->schedule->heartbeat->complete flow closes the execution
    as COMPLETED in history -- assert the consequence, not each call's status."""
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

    activity_type_name = ctx.unique_name("sim2real-swf-actype-")
    swf.register_activity_type(
        domain=domain,
        name=activity_type_name,
        version="1.0",
        defaultTaskStartToCloseTimeout="30",
        defaultTaskHeartbeatTimeout="30",
        defaultTaskList=task_list,
        defaultTaskScheduleToStartTimeout="30",
        defaultTaskScheduleToCloseTimeout="60",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": activity_type_name, "version": "1.0"}))

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    start_resp = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_type_name, "version": "1.0"},
        taskList=task_list,
        input="start-input",
    )
    run_id = start_resp["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}

    # Step 1: decider receives the initial decision task and schedules the activity.
    decision_task = _poll_for_decision_task(ctx, domain, task_list)
    assert decision_task.get("taskToken"), f"expected a decision task token, got {decision_task!r}"
    swf.respond_decision_task_completed(
        taskToken=decision_task["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityId": "activity-1",
                    "activityType": {"name": activity_type_name, "version": "1.0"},
                    "taskList": task_list,
                    "input": "activity-input",
                },
            }
        ],
    )

    # Step 2: activity worker picks up the scheduled activity, heartbeats, then completes it.
    activity_task = _poll_for_activity_task(ctx, domain, task_list)
    assert activity_task.get("taskToken"), f"expected an activity task token, got {activity_task!r}"
    assert activity_task["activityId"] == "activity-1", (
        f"expected activityId 'activity-1', got {activity_task['activityId']!r}"
    )
    heartbeat_resp = swf.record_activity_task_heartbeat(taskToken=activity_task["taskToken"])
    assert heartbeat_resp["cancelRequested"] is False, (
        f"expected cancelRequested False on an un-cancelled execution, got {heartbeat_resp['cancelRequested']!r}"
    )
    swf.respond_activity_task_completed(
        taskToken=activity_task["taskToken"], result="activity-result"
    )

    # Step 3: decider receives the follow-up decision task and closes the workflow.
    decision_task_2 = _poll_for_decision_task(ctx, domain, task_list)
    assert decision_task_2.get("taskToken"), f"expected a follow-up decision task token, got {decision_task_2!r}"
    swf.respond_decision_task_completed(
        taskToken=decision_task_2["taskToken"],
        decisions=[
            {
                "decisionType": "CompleteWorkflowExecution",
                "completeWorkflowExecutionDecisionAttributes": {"result": "final-result"},
            }
        ],
    )

    # Assert the CONSEQUENCE: the execution observably closes as COMPLETED.
    events = _poll_until_closed(ctx, domain, execution)
    described = swf.describe_workflow_execution(domain=domain, execution=execution)
    assert described["executionInfo"]["executionStatus"] == "CLOSED", (
        f"expected executionStatus 'CLOSED', got {described['executionInfo']['executionStatus']!r}"
    )
    assert described["executionInfo"]["closeStatus"] == "COMPLETED", (
        f"expected closeStatus 'COMPLETED', got {described['executionInfo']['closeStatus']!r}"
    )

    event_types = [e["eventType"] for e in events]
    assert "ActivityTaskScheduled" in event_types, (
        f"expected 'ActivityTaskScheduled' in history, got {event_types!r}"
    )
    assert "ActivityTaskCompleted" in event_types, (
        f"expected 'ActivityTaskCompleted' in history, got {event_types!r}"
    )
    assert event_types[-1] == "WorkflowExecutionCompleted", (
        f"expected the final history event to be 'WorkflowExecutionCompleted', got {event_types[-1]!r}"
    )


def _poll_for_decision_task(ctx, domain, task_list, timeout_s=70.0):
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.poll_for_decision_task(domain=domain, taskList=task_list)
        if resp.get("taskToken"):
            return resp
    raise AssertionError("no decision task became available within timeout")


def _poll_for_activity_task(ctx, domain, task_list, timeout_s=70.0):
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.poll_for_activity_task(domain=domain, taskList=task_list)
        if resp.get("taskToken"):
            return resp
    raise AssertionError("no activity task became available within timeout")


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
