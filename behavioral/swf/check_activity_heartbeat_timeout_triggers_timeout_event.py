"""activity-heartbeat-timeout-triggers-timeout-event."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-heartbeat-timeout-triggers-timeout-event"
GROUP = "visibility-timeout-ttl"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An activity that stops heartbeating records ActivityTaskTimedOut HEARTBEAT, and RespondActivityTaskCompleted
    with its stale token is refused with UnknownResourceFault and its exact message, adding no ActivityTaskCompleted;
    a second, healthy activity on the same execution then completes normally."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)
    act_type = _register_activity_type(ctx, domain, task_list)

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, task_list)

    dtask = _poll_decision_until_task(ctx, domain, task_list)
    swf.respond_decision_task_completed(
        taskToken=dtask["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_type[0], "version": act_type[1]},
                    "activityId": "act-1",
                    "taskList": {"name": task_list},
                    "scheduleToStartTimeout": "60",
                    "scheduleToCloseTimeout": "180",
                    "startToCloseTimeout": "120",
                    "heartbeatTimeout": "6",
                },
            }
        ],
    )

    atask = _poll_activity_until_task(ctx, domain, task_list)
    assert atask["taskToken"], "activity task token missing"

    # Deliberately never heartbeat; poll history for the server-emitted timeout.
    events = _poll_until(
        lambda: _get_history(ctx, domain, workflow_id, run_id),
        lambda evs: any(e["eventType"] == "ActivityTaskTimedOut" for e in evs),
        timeout_s=90.0,
        interval_s=3.0,
    )
    timeout_event = next(e for e in events if e["eventType"] == "ActivityTaskTimedOut")
    actual_timeout_type = timeout_event["activityTaskTimedOutEventAttributes"]["timeoutType"]
    assert actual_timeout_type == "HEARTBEAT", f"expected HEARTBEAT timeout, got {actual_timeout_type!r}"

    code, message = _error(
        lambda: swf.respond_activity_task_completed(
            taskToken=atask["taskToken"], result="too-late"
        )
    )
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault, got {code!r}"
    timed_out_scheduled_id = timeout_event["activityTaskTimedOutEventAttributes"]["scheduledEventId"]
    expected_message = f"Unknown activity, scheduledEventId = {timed_out_scheduled_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # And history was NOT mutated by the rejected call: no ActivityTaskCompleted recorded.
    mid_events = _get_history(ctx, domain, workflow_id, run_id)
    assert not any(e["eventType"] == "ActivityTaskCompleted" for e in mid_events), (
        "ActivityTaskCompleted must not appear for the rejected, timed-out response"
    )

    # Positive control: the timeout triggers a fresh decision task; schedule and
    # complete a second, healthy activity task normally, proving the rejection above
    # is specific to the stale token rather than a blanket refusal.
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
    assert fresh_task["activityId"] == "act-fresh", fresh_task.get("activityId")
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
    completed_id = completed_activity["activityTaskScheduledEventAttributes"]["activityId"]
    assert completed_id == "act-fresh", f"expected completed activity 'act-fresh', got {completed_id!r}"


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises. An unexpected success raises, so an
    emulator accepting a call AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    type_ref = {"name": params["name"], "version": params["version"]}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", type_ref))
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
    type_ref = {"name": params["name"], "version": params["version"]}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", type_ref))
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
