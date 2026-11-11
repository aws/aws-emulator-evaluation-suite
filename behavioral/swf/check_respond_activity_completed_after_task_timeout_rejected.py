"""respond-activity-completed-after-task-timeout-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "respond-activity-completed-after-task-timeout-rejected"
GROUP = "overly-permissive"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RespondActivityTaskCompleted using a taskToken whose activity already timed
    out (START_TO_CLOSE) is rejected rather than mutating history after the fact; a
    fresh activity task on the same execution still completes normally."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)
    act_type = _register_activity_type(ctx, domain, task_list)

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, task_list)

    dtask1 = _poll_decision_until_task(ctx, domain, task_list)
    swf.respond_decision_task_completed(
        taskToken=dtask1["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_type[0], "version": act_type[1]},
                    "activityId": "act-stale",
                    "taskList": {"name": task_list},
                    "scheduleToStartTimeout": "60",
                    "scheduleToCloseTimeout": "180",
                    "startToCloseTimeout": "6",
                    "heartbeatTimeout": "60",
                },
            }
        ],
    )
    stale_task = _poll_activity_until_task(ctx, domain, task_list)
    assert stale_task["activityId"] == "act-stale", (
        f"expected activityId 'act-stale', got {stale_task['activityId']!r}"
    )

    # Never respond; wait for the server-side START_TO_CLOSE timeout.
    events = _poll_until(
        lambda: _get_history(ctx, domain, workflow_id, run_id),
        lambda evs: any(e["eventType"] == "ActivityTaskTimedOut" for e in evs),
        timeout_s=90.0,
        interval_s=3.0,
    )
    timedout = next(e for e in events if e["eventType"] == "ActivityTaskTimedOut")
    actual_timeout_type = timedout["activityTaskTimedOutEventAttributes"]["timeoutType"]
    assert actual_timeout_type == "START_TO_CLOSE", (
        f"expected timeoutType 'START_TO_CLOSE', got {actual_timeout_type!r}"
    )

    code, message = _error(
        lambda: swf.respond_activity_task_completed(taskToken=stale_task["taskToken"], result="too-late")
    )
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault, got {code!r}"
    scheduled_id = timedout["activityTaskTimedOutEventAttributes"]["scheduledEventId"]
    expected = f"Unknown activity, scheduledEventId = {scheduled_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no ActivityTaskCompleted was recorded for the stale token.
    mid_events = _get_history(ctx, domain, workflow_id, run_id)
    stale_completed = [e for e in mid_events if e["eventType"] == "ActivityTaskCompleted"]
    assert not stale_completed, (
        f"expected no ActivityTaskCompleted for the stale token, found {stale_completed!r}"
    )

    # Positive control: the timeout triggers a fresh decision task; schedule and
    # complete a second, healthy activity task normally.
    dtask2 = _poll_decision_until_task(ctx, domain, task_list)
    swf.respond_decision_task_completed(
        taskToken=dtask2["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_type[0], "version": act_type[1]},
                    "activityId": "act-fresh",
                    "taskList": {"name": task_list},
                    "scheduleToStartTimeout": "60",
                    "scheduleToCloseTimeout": "180",
                    "startToCloseTimeout": "60",
                    "heartbeatTimeout": "60",
                },
            }
        ],
    )
    fresh_task = _poll_activity_until_task(ctx, domain, task_list)
    assert fresh_task["activityId"] == "act-fresh", (
        f"expected activityId 'act-fresh', got {fresh_task['activityId']!r}"
    )
    swf.respond_activity_task_completed(taskToken=fresh_task["taskToken"], result="ok")

    final_events = _poll_until(
        lambda: _get_history(ctx, domain, workflow_id, run_id),
        lambda evs: any(e["eventType"] == "ActivityTaskCompleted" for e in evs),
        timeout_s=30.0,
        interval_s=2.0,
    )
    completed = next(e for e in final_events if e["eventType"] == "ActivityTaskCompleted")
    completed_activity = next(
        e for e in final_events
        if e["eventId"] == completed["activityTaskCompletedEventAttributes"]["scheduledEventId"]
    )
    completed_activity_id = completed_activity["activityTaskScheduledEventAttributes"]["activityId"]
    assert completed_activity_id == "act-fresh", (
        f"expected the completed activity to be 'act-fresh', got {completed_activity_id!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _register_workflow_type(ctx, domain: str, task_list: str, **overrides: Any) -> tuple[str, str]:
    swf = ctx.client("swf")
    name = ctx.unique_name("sim2real-swf-wft-")
    version = "1.0"
    params: dict[str, Any] = dict(
        domain=domain,
        name=name,
        version=version,
        defaultTaskStartToCloseTimeout="30",
        defaultExecutionStartToCloseTimeout="300",
        defaultTaskList={"name": task_list},
        defaultChildPolicy="TERMINATE",
    )
    params.update(overrides)
    swf.register_workflow_type(**params)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": name, "version": version}))
    return name, version


def _register_activity_type(ctx, domain: str, task_list: str, **overrides: Any) -> tuple[str, str]:
    swf = ctx.client("swf")
    name = ctx.unique_name("sim2real-swf-act-")
    version = "1.0"
    params: dict[str, Any] = dict(
        domain=domain,
        name=name,
        version=version,
        defaultTaskStartToCloseTimeout="60",
        defaultTaskHeartbeatTimeout="60",
        defaultTaskList={"name": task_list},
        defaultTaskScheduleToStartTimeout="60",
        defaultTaskScheduleToCloseTimeout="120",
    )
    params.update(overrides)
    swf.register_activity_type(**params)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": name, "version": version}))
    return name, version


def _start_workflow(
    ctx, domain: str, workflow_id: str, wf_type: tuple[str, str], task_list: str, **overrides: Any
) -> str:
    swf = ctx.client("swf")
    params: dict[str, Any] = dict(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_type[0], "version": wf_type[1]},
        taskList={"name": task_list},
    )
    params.update(overrides)
    resp = swf.start_workflow_execution(**params)
    run_id = resp["runId"]

    def _cleanup():
        try:
            swf.terminate_workflow_execution(
                domain=domain, workflowId=workflow_id, runId=run_id, reason="test-cleanup"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UnknownResourceFault":
                raise

    ctx.on_cleanup(_cleanup)
    return run_id


def _get_history(ctx, domain: str, workflow_id: str, run_id: str) -> list[dict[str, Any]]:
    swf = ctx.client("swf")
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"domain": domain, "execution": {"workflowId": workflow_id, "runId": run_id}}
        if token:
            kwargs["nextPageToken"] = token
        resp = swf.get_workflow_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextPageToken")
        if not token:
            break
    return events


def _poll_until(probe, predicate, timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_decision_until_task(ctx, domain: str, task_list: str, timeout_s: float = 90.0) -> dict[str, Any]:
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
        if resp.get("taskToken"):
            return resp
    raise AssertionError(f"no decision task delivered on {task_list!r} within {timeout_s}s")


def _poll_activity_until_task(ctx, domain: str, task_list: str, timeout_s: float = 90.0) -> dict[str, Any]:
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.poll_for_activity_task(domain=domain, taskList={"name": task_list})
        if resp.get("taskToken"):
            return resp
    raise AssertionError(f"no activity task delivered on {task_list!r} within {timeout_s}s")


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
