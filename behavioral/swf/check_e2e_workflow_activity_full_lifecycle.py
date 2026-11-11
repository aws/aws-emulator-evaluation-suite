"""e2e-workflow-activity-full-lifecycle."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-workflow-activity-full-lifecycle"
GROUP = "e2e"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A decision schedules an activity, the activity heartbeats and completes, and a second decision closes the
    workflow: the execution ends CLOSED/COMPLETED and is listed so by ListClosedWorkflowExecutions."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)
    act_type = _register_activity_type(ctx, domain, task_list)

    workflow_id = ctx.unique_name("sim2real-exec-")
    start_time = datetime.datetime.now(datetime.timezone.utc)
    start_resp = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType=wf_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout="300",
        taskStartToCloseTimeout="30",
        childPolicy="TERMINATE",
    )
    run_id = start_resp["runId"]
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, workflow_id))

    # 1. First decision task: schedule the activity.
    decision_task_1 = _poll_decision_task(ctx, domain, task_list)
    assert decision_task_1.get("taskToken"), f"no decision task became available: {decision_task_1!r}"
    activity_id = ctx.unique_name("sim2real-act-id-")
    swf.respond_decision_task_completed(
        taskToken=decision_task_1["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": act_type,
                    "activityId": activity_id,
                    "taskList": {"name": task_list},
                    "scheduleToStartTimeout": "30",
                    "scheduleToCloseTimeout": "60",
                    "startToCloseTimeout": "30",
                    "heartbeatTimeout": "30",
                    "input": "do-the-work",
                },
            }
        ],
    )

    # 2. Activity task: heartbeat then complete.
    activity_task = _poll_activity_task(ctx, domain, task_list)
    assert activity_task.get("taskToken"), f"no activity task became available: {activity_task!r}"
    assert activity_task["activityId"] == activity_id, (
        f"expected activityId {activity_id!r}, got {activity_task['activityId']!r}"
    )
    heartbeat = swf.record_activity_task_heartbeat(taskToken=activity_task["taskToken"], details="working")
    assert heartbeat["cancelRequested"] is False, f"expected cancelRequested False, got {heartbeat!r}"
    swf.respond_activity_task_completed(taskToken=activity_task["taskToken"], result="work-done")

    # 3. Second decision task: close the workflow.
    decision_task_2 = _poll_decision_task(ctx, domain, task_list)
    assert decision_task_2.get("taskToken"), f"no follow-up decision task became available: {decision_task_2!r}"
    event_types = [e["eventType"] for e in decision_task_2["events"]]
    assert "ActivityTaskCompleted" in event_types, (
        f"expected ActivityTaskCompleted in decision task events, got {event_types!r}"
    )
    swf.respond_decision_task_completed(
        taskToken=decision_task_2["taskToken"],
        decisions=[
            {
                "decisionType": "CompleteWorkflowExecution",
                "completeWorkflowExecutionDecisionAttributes": {"result": "all-done"},
            }
        ],
    )

    # 4. Poll DescribeWorkflowExecution until CLOSED/COMPLETED.
    execution = {"workflowId": workflow_id, "runId": run_id}
    final_info = _poll_until_closed(ctx, domain, execution)
    assert final_info["executionStatus"] == "CLOSED", (
        f"expected executionStatus CLOSED, got {final_info['executionStatus']!r}"
    )
    assert final_info["closeStatus"] == "COMPLETED", (
        f"expected closeStatus COMPLETED, got {final_info.get('closeStatus')!r}"
    )

    # 5. Confirm visibility in ListClosedWorkflowExecutions.
    closed = _poll_closed_visibility(ctx, domain, workflow_id, start_time)
    assert closed is not None, "execution never appeared in ListClosedWorkflowExecutions"
    assert closed["executionStatus"] == "CLOSED", (
        f"expected executionStatus CLOSED in ListClosedWorkflowExecutions, got {closed['executionStatus']!r}"
    )
    assert closed["closeStatus"] == "COMPLETED", (
        f"expected closeStatus COMPLETED in ListClosedWorkflowExecutions, got {closed.get('closeStatus')!r}"
    )


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


def _register_activity_type(ctx, domain: str, task_list: str) -> dict:
    swf = ctx.client("swf")
    name = ctx.unique_name("sim2real-act-")
    version = "1.0"
    swf.register_activity_type(
        domain=domain,
        name=name,
        version=version,
        defaultTaskStartToCloseTimeout="30",
        defaultTaskScheduleToCloseTimeout="60",
        defaultTaskScheduleToStartTimeout="30",
        defaultTaskHeartbeatTimeout="30",
        defaultTaskList={"name": task_list},
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": name, "version": version}))
    return {"name": name, "version": version}


def _poll_decision_task(ctx, domain: str, task_list: str, attempts: int = 3) -> dict:
    swf = ctx.client("swf")
    task: dict = {}
    for _ in range(attempts):
        task = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
        if task.get("taskToken"):
            return task
        time.sleep(1)
    return task


def _poll_activity_task(ctx, domain: str, task_list: str, attempts: int = 3) -> dict:
    swf = ctx.client("swf")
    task: dict = {}
    for _ in range(attempts):
        task = swf.poll_for_activity_task(domain=domain, taskList={"name": task_list})
        if task.get("taskToken"):
            return task
        time.sleep(1)
    return task


def _poll_until_closed(ctx, domain: str, execution: dict, timeout_s: float = 30.0) -> dict:
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    info: dict = {}
    while time.monotonic() < deadline:
        info = swf.describe_workflow_execution(domain=domain, execution=execution)["executionInfo"]
        if info["executionStatus"] == "CLOSED":
            return info
        time.sleep(1)
    raise AssertionError(f"workflow execution never closed within {timeout_s}s, last info={info}")


def _poll_closed_visibility(ctx, domain: str, workflow_id: str, start_time, timeout_s: float = 60.0):
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.list_closed_workflow_executions(
            domain=domain,
            startTimeFilter={"oldestDate": start_time},
            executionFilter={"workflowId": workflow_id},
        )
        infos = resp.get("executionInfos", [])
        if infos:
            return infos[0]
        time.sleep(2)
    return None


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
