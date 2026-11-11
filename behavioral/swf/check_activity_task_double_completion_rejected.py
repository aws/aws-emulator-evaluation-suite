"""activity-task-double-completion-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-task-double-completion-rejected"
GROUP = "e2e"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second RespondActivityTaskCompleted on an already-completed task token is
    rejected with UnknownResourceFault, the history still records exactly one
    completion, and the original (positive-control) completion is unaffected."""
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
    )
    run_id = start_resp["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}
    ctx.on_cleanup(
        lambda: swf.terminate_workflow_execution(
            domain=domain, workflowId=workflow_id, runId=run_id
        )
    )

    decision_task = _poll_for_decision_task(ctx, domain, task_list)
    swf.respond_decision_task_completed(
        taskToken=decision_task["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityId": "activity-1",
                    "activityType": {"name": activity_type_name, "version": "1.0"},
                    "taskList": task_list,
                },
            }
        ],
    )

    activity_task = _poll_for_activity_task(ctx, domain, task_list)
    task_token = activity_task["taskToken"]

    # POSITIVE CONTROL: the first completion must succeed.
    swf.respond_activity_task_completed(taskToken=task_token, result="first-result")

    # Let the completion land in history before probing the negative.
    _poll_for_event(ctx, domain, execution, "ActivityTaskCompleted")

    # NEGATIVE: a second completion on the same (now-consumed) token must be rejected.
    code, message = _error(lambda: swf.respond_activity_task_completed(
        taskToken=task_token, result="second-result"
    ))
    assert code == "UnknownResourceFault", (
        f"expected UnknownResourceFault when re-completing an already-completed task, got {code!r}"
    )

    # EFFECT ABSENT: history still records exactly one ActivityTaskCompleted event,
    # and its result is the one from the positive control, not the rejected retry.
    history = swf.get_workflow_execution_history(domain=domain, execution=execution)
    completed_events = [
        e for e in history["events"] if e["eventType"] == "ActivityTaskCompleted"
    ]
    assert len(completed_events) == 1, (
        f"expected exactly one ActivityTaskCompleted event, found {len(completed_events)}"
    )
    completed_scheduled_id = completed_events[0]["activityTaskCompletedEventAttributes"]["scheduledEventId"]
    expected_message = f"Unknown activity, scheduledEventId = {completed_scheduled_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    actual_result = completed_events[0]["activityTaskCompletedEventAttributes"]["result"]
    assert actual_result == "first-result", (
        f"expected the retained event to carry the positive control's result 'first-result', "
        f"got {actual_result!r}"
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


def _poll_for_event(ctx, domain, execution, event_type, timeout_s=30.0, interval_s=1.5):
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.get_workflow_execution_history(domain=domain, execution=execution)
        if any(e["eventType"] == event_type for e in resp["events"]):
            return resp["events"]
        time.sleep(interval_s)
    raise AssertionError(f"{event_type} never appeared in history within {timeout_s}s")


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
