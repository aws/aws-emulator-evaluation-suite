"""workflow-history-event-ordering-monotonic."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workflow-history-event-ordering-monotonic"
GROUP = "ordering"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """History events are delivered in strictly increasing eventId order matching causal sequence."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    wf_type = _register_workflow_type(ctx, domain, ctx.unique_name("sim2real-swf-wft-"))
    act_type = _register_activity_type(ctx, domain, ctx.unique_name("sim2real-swf-act-"))
    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    decision_tl = ctx.unique_name("sim2real-swf-dtl-")
    activity_tl = ctx.unique_name("sim2real-swf-atl-")

    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, decision_tl)
    execution = {"workflowId": workflow_id, "runId": run_id}

    # Decision #1: schedule an activity task.
    d1 = swf.poll_for_decision_task(domain=domain, taskList={"name": decision_tl})
    assert d1.get("taskToken"), f"no decision task delivered on {decision_tl!r}: {d1!r}"
    swf.respond_decision_task_completed(
        taskToken=d1["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": act_type,
                    "activityId": "act-1",
                    "taskList": {"name": activity_tl},
                    "scheduleToCloseTimeout": "60",
                    "scheduleToStartTimeout": "60",
                    "startToCloseTimeout": "60",
                    "heartbeatTimeout": "60",
                },
            }
        ],
    )

    activity = swf.poll_for_activity_task(domain=domain, taskList={"name": activity_tl})
    assert activity.get("taskToken"), f"no activity task delivered on {activity_tl!r}: {activity!r}"
    swf.respond_activity_task_completed(taskToken=activity["taskToken"], result="ok")

    # Decision #2: sees ActivityTaskCompleted and closes the workflow.
    d2 = swf.poll_for_decision_task(domain=domain, taskList={"name": decision_tl})
    assert d2.get("taskToken"), f"no second decision task delivered on {decision_tl!r}: {d2!r}"
    swf.respond_decision_task_completed(
        taskToken=d2["taskToken"],
        decisions=[
            {
                "decisionType": "CompleteWorkflowExecution",
                "completeWorkflowExecutionDecisionAttributes": {"result": "done"},
            }
        ],
    )

    history = swf.get_workflow_execution_history(domain=domain, execution=execution)
    events = history["events"]
    event_ids = [e["eventId"] for e in events]
    event_types = [e["eventType"] for e in events]

    # Strictly increasing, gap-free eventIds starting at 1.
    assert event_ids == list(range(1, len(event_ids) + 1)), f"non-monotonic eventIds: {event_ids}"

    scheduled_idx = event_types.index("ActivityTaskScheduled")
    started_idx = event_types.index("ActivityTaskStarted")
    completed_idx = event_types.index("ActivityTaskCompleted")
    assert event_types[0] == "WorkflowExecutionStarted", (
        f"expected first event WorkflowExecutionStarted, got {event_types[0]}"
    )
    assert event_types[-1] == "WorkflowExecutionCompleted", (
        f"expected last event WorkflowExecutionCompleted, got {event_types[-1]}"
    )
    assert scheduled_idx < started_idx < completed_idx, (
        f"activity lifecycle events out of causal order: {event_types}"
    )
    closed_idx = event_types.index("WorkflowExecutionCompleted")
    assert completed_idx < closed_idx, (
        f"expected ActivityTaskCompleted (idx {completed_idx}) before "
        f"WorkflowExecutionCompleted (idx {closed_idx})"
    )


def _register_workflow_type(ctx, domain: str, name: str, version: str = "1.0") -> dict:
    swf = ctx.client("swf")
    swf.register_workflow_type(domain=domain, name=name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": name, "version": version}))
    return {"name": name, "version": version}


def _register_activity_type(ctx, domain: str, name: str, version: str = "1.0") -> dict:
    swf = ctx.client("swf")
    swf.register_activity_type(domain=domain, name=name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": name, "version": version}))
    return {"name": name, "version": version}


def _start_workflow(
    ctx,
    domain: str,
    workflow_id: str,
    workflow_type: dict,
    task_list: str,
    exec_timeout: str = "3600",
    task_timeout: str = "60",
) -> str:
    swf = ctx.client("swf")
    resp = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType=workflow_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout=exec_timeout,
        taskStartToCloseTimeout=task_timeout,
        childPolicy="TERMINATE",
    )
    return resp["runId"]


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
