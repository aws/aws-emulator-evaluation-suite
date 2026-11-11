"""respond-activity-task-completed-twice-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "respond-activity-task-completed-twice-rejected"
GROUP = "overly-permissive"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second RespondActivityTaskCompleted with the same token fails with UnknownResourceFault and its exact message,
    and history keeps exactly one ActivityTaskCompleted, carrying the first result."""
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
    run_id = start_resp["runId"]
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, workflow_id))

    decision_task = _poll_decision_task(ctx, domain, task_list)
    assert decision_task.get("taskToken"), "no decision task became available to schedule the activity"
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
    assert activity_task.get("taskToken"), "no activity task became available after scheduling it"
    token = activity_task["taskToken"]

    # Positive control: the first completion succeeds.
    swf.respond_activity_task_completed(taskToken=token, result="first-result")

    # Break exactly one thing: complete the SAME task again with the SAME token.
    def _complete_again():
        swf.respond_activity_task_completed(taskToken=token, result="second-result")

    code, message = _error(_complete_again)
    assert code == "UnknownResourceFault", f"unexpected error code: {code}"

    # Effect absent: history still shows exactly one ActivityTaskCompleted event, carrying the
    # FIRST (accepted) result, never the duplicate's.
    history = swf.get_workflow_execution_history(
        domain=domain, execution={"workflowId": workflow_id, "runId": run_id}, maximumPageSize=200
    )["events"]
    started = next(e for e in history if e["eventId"] == activity_task["startedEventId"])
    scheduled_id = started["activityTaskStartedEventAttributes"]["scheduledEventId"]
    expected = f"Unknown activity, scheduledEventId = {scheduled_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    completed = [e for e in history if e["eventType"] == "ActivityTaskCompleted"]
    assert len(completed) == 1, f"expected exactly one ActivityTaskCompleted event, found {len(completed)}"
    actual_result = completed[0]["activityTaskCompletedEventAttributes"]["result"]
    assert actual_result == "first-result", (
        f"expected the retained ActivityTaskCompleted result to be the positive control's "
        f"'first-result', the duplicate must have had no effect; got {actual_result!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected UnknownResourceFault but the call SUCCEEDED: {result!r}")


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


def _poll_decision_task(ctx, domain: str, task_list: str, timeout_s: float = 60.0) -> dict:
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        task = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
        if task.get("taskToken"):
            return task
    raise AssertionError(f"no decision task became available within {timeout_s}s")


def _poll_activity_task(ctx, domain: str, task_list: str, timeout_s: float = 60.0) -> dict:
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        task = swf.poll_for_activity_task(domain=domain, taskList={"name": task_list})
        if task.get("taskToken"):
            return task
    raise AssertionError(f"no activity task became available within {timeout_s}s")


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
