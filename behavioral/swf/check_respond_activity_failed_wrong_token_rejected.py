"""respond-activity-failed-wrong-token-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "respond-activity-failed-wrong-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RespondActivityTaskFailed with the token of a completed activity task fails with UnknownResourceFault and its
    exact message and records no ActivityTaskFailed; a fresh activity task is then failed with its own token."""
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
        decisions=[_schedule_decision(act_type, "act-first", task_list)],
    )
    first_task = _poll_activity_until_task(ctx, domain, task_list)
    assert first_task["activityId"] == "act-first", (
        f"expected activityId 'act-first', polled {first_task['activityId']!r}"
    )
    swf.respond_activity_task_completed(taskToken=first_task["taskToken"], result="done")

    first_events = _poll_until(
        lambda: _get_history(ctx, domain, workflow_id, run_id),
        lambda evs: any(e["eventType"] == "ActivityTaskCompleted" for e in evs),
        timeout_s=30.0,
        interval_s=2.0,
    )
    first_completed = next(e for e in first_events if e["eventType"] == "ActivityTaskCompleted")
    first_scheduled_id = first_completed["activityTaskCompletedEventAttributes"]["scheduledEventId"]

    # Reusing the closed taskToken to fail the (already completed) task must be rejected.
    code, message = _error(
        lambda: swf.respond_activity_task_failed(
            taskToken=first_task["taskToken"], reason="too-late", details="stale-token"
        )
    )
    assert code == "UnknownResourceFault", (
        f"expected UnknownResourceFault for a stale taskToken, got {code!r}"
    )
    expected = f"Unknown activity, scheduledEventId = {first_scheduled_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no ActivityTaskFailed event was recorded; the task remains Completed.
    mid_events = _get_history(ctx, domain, workflow_id, run_id)
    assert not any(e["eventType"] == "ActivityTaskFailed" for e in mid_events), (
        "expected no ActivityTaskFailed event after the rejected stale-token call, but one was recorded"
    )
    assert any(e["eventType"] == "ActivityTaskCompleted" for e in mid_events), (
        "expected the original ActivityTaskCompleted event to still be present in history"
    )

    # Positive control: a fresh activity task can be failed with its own valid token.
    dtask2 = _poll_decision_until_task(ctx, domain, task_list)
    swf.respond_decision_task_completed(
        taskToken=dtask2["taskToken"],
        decisions=[_schedule_decision(act_type, "act-second", task_list)],
    )
    second_task = _poll_activity_until_task(ctx, domain, task_list)
    assert second_task["activityId"] == "act-second", (
        f"expected activityId 'act-second', polled {second_task['activityId']!r}"
    )
    swf.respond_activity_task_failed(
        taskToken=second_task["taskToken"], reason="deliberate-fail", details="control"
    )

    final_events = _poll_until(
        lambda: _get_history(ctx, domain, workflow_id, run_id),
        lambda evs: any(e["eventType"] == "ActivityTaskFailed" for e in evs),
        timeout_s=30.0,
        interval_s=2.0,
    )
    failed = next(e for e in final_events if e["eventType"] == "ActivityTaskFailed")
    failed_activity = next(
        e for e in final_events
        if e["eventId"] == failed["activityTaskFailedEventAttributes"]["scheduledEventId"]
    )
    assert failed_activity["activityTaskScheduledEventAttributes"]["activityId"] == "act-second", (
        "expected the ActivityTaskFailed event to trace back to the fresh 'act-second' schedule, "
        f"got {failed_activity['activityTaskScheduledEventAttributes']['activityId']!r}"
    )


def _schedule_decision(act_type: tuple[str, str], activity_id: str, task_list: str) -> dict[str, Any]:
    return {
        "decisionType": "ScheduleActivityTask",
        "scheduleActivityTaskDecisionAttributes": {
            "activityType": {"name": act_type[0], "version": act_type[1]},
            "activityId": activity_id,
            "taskList": {"name": task_list},
            "scheduleToStartTimeout": "60",
            "scheduleToCloseTimeout": "180",
            "startToCloseTimeout": "60",
            "heartbeatTimeout": "60",
        },
    }


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
