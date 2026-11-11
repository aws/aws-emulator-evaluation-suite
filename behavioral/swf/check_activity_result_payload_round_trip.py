"""activity-result-payload-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "activity-result-payload-round-trip"
GROUP = "representation"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The result string passed to RespondActivityTaskCompleted -- including a large numeric
    string and unicode -- survives unchanged in the ActivityTaskCompleted history event."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)
    act_type = _register_activity_type(ctx, domain, task_list)

    workflow_id = ctx.unique_name("sim2real-exec-")
    start_resp = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType=wf_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout="300",
        taskStartToCloseTimeout="30",
        childPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, workflow_id))
    run_id = start_resp["runId"]

    decision_task = _poll_decision_task(ctx, domain, task_list)
    assert decision_task.get("taskToken"), f"expected a decision task token, got {decision_task!r}"

    activity_id = ctx.unique_name("sim2real-act-id-")
    swf.respond_decision_task_completed(
        taskToken=decision_task["taskToken"],
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
                    "input": "activity-input",
                },
            }
        ],
    )

    activity_task = _poll_activity_task(ctx, domain, task_list)
    assert activity_task.get("taskToken"), f"expected an activity task token, got {activity_task!r}"

    payload = (
        "9876543210987654321098765432109876543210987654321098765432109876543210"
        + "-unicode-h\u00e9llo-\u65e5\u672c\u8a9e-\U0001f389-"
        + "1234567890" * 4
    )
    swf.respond_activity_task_completed(taskToken=activity_task["taskToken"], result=payload)

    history = swf.get_workflow_execution_history(
        domain=domain,
        execution={"workflowId": workflow_id, "runId": run_id},
        maximumPageSize=200,
    )["events"]
    completed = [e for e in history if e["eventType"] == "ActivityTaskCompleted"]
    assert len(completed) == 1, f"expected exactly 1 ActivityTaskCompleted event, got {len(completed)}"
    result = completed[0]["activityTaskCompletedEventAttributes"]["result"]
    assert result == payload, "activity result payload was mutated in the history event"


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
    for _ in range(attempts):
        task = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
        if task.get("taskToken"):
            return task
        time.sleep(1)
    return task


def _poll_activity_task(ctx, domain: str, task_list: str, attempts: int = 3) -> dict:
    swf = ctx.client("swf")
    for _ in range(attempts):
        task = swf.poll_for_activity_task(domain=domain, taskList={"name": task_list})
        if task.get("taskToken"):
            return task
        time.sleep(1)
    return task


def _safe_terminate(ctx, domain: str, workflow_id: str) -> None:
    swf = ctx.client("swf")
    try:
        swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


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
