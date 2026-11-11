"""timer-start-fire-cancel-and-unknown-cancel."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "timer-start-fire-cancel-and-unknown-cancel"
GROUP = "timers"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """StartTimer records TimerStarted and counts in openTimers, CancelTimer of an unknown id records CancelTimerFailed
    TIMER_ID_UNKNOWN, CancelTimer of a running timer records TimerCanceled, and a 2 s timer fires to the decider."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-behav-swf-tl-")
    wf_name = ctx.unique_name("sim2real-behav-swf-wft-")
    swf.register_workflow_type(
        domain=domain, name=wf_name, version="1.0",
        defaultTaskStartToCloseTimeout="60", defaultExecutionStartToCloseTimeout="600",
        defaultTaskList={"name": task_list}, defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": "1.0"}))
    workflow_id = ctx.unique_name("sim2real-behav-swf-wf-")
    run_id = swf.start_workflow_execution(
        domain=domain, workflowId=workflow_id, workflowType={"name": wf_name, "version": "1.0"},
        taskList={"name": task_list},
    )["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}
    ctx.on_cleanup(_teardown(
        lambda: swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id,
                                                 runId=run_id, reason="sim2real cleanup"),
        "UnknownResourceFault"))

    first = _next_decision(swf, domain, task_list)
    swf.respond_decision_task_completed(taskToken=first["taskToken"], decisions=[
        {"decisionType": "StartTimer", "startTimerDecisionAttributes": {
            "timerId": "long", "startToFireTimeout": "3600", "control": "long-control"}},
        {"decisionType": "CancelTimer", "cancelTimerDecisionAttributes": {"timerId": "never-started"}},
    ])

    second = _next_decision(swf, domain, task_list)
    new_types = [e["eventType"] for e in second["events"] if e["eventId"] > second["previousStartedEventId"]]
    assert "CancelTimerFailed" in new_types, (
        f"the failed CancelTimer did not reach the decider; new events were {new_types!r}"
    )
    open_counts = swf.describe_workflow_execution(domain=domain, execution=execution)["openCounts"]
    assert open_counts["openTimers"] == 1, f"openTimers with one running timer was {open_counts['openTimers']!r}"

    swf.respond_decision_task_completed(taskToken=second["taskToken"], decisions=[
        {"decisionType": "CancelTimer", "cancelTimerDecisionAttributes": {"timerId": "long"}},
        {"decisionType": "StartTimer", "startTimerDecisionAttributes": {
            "timerId": "short", "startToFireTimeout": "2"}},
    ])

    fired_task = None
    deadline = time.monotonic() + 120.0
    while fired_task is None and time.monotonic() < deadline:
        task = _next_decision(swf, domain, task_list)
        fresh = [e["eventType"] for e in task["events"] if e["eventId"] > task["previousStartedEventId"]]
        if "TimerFired" in fresh:
            fired_task = task
        else:
            swf.respond_decision_task_completed(taskToken=task["taskToken"], decisions=[])
    assert fired_task is not None, "the 2 s timer never fired into a decision task within 120 s"

    open_counts = swf.describe_workflow_execution(domain=domain, execution=execution)["openCounts"]
    assert open_counts["openTimers"] == 0, (
        f"openTimers after one timer was canceled and the other fired was {open_counts['openTimers']!r}"
    )
    swf.respond_decision_task_completed(taskToken=fired_task["taskToken"], decisions=[
        {"decisionType": "CompleteWorkflowExecution",
         "completeWorkflowExecutionDecisionAttributes": {"result": "done"}}])

    events = _history(swf, domain, execution)
    by_id = {e["eventId"]: e for e in events}
    started = {e["timerStartedEventAttributes"]["timerId"]: e
               for e in events if e["eventType"] == "TimerStarted"}
    assert sorted(started) == ["long", "short"], f"TimerStarted timer ids were {sorted(started)!r}"
    long_attrs = started["long"]["timerStartedEventAttributes"]
    assert (long_attrs["startToFireTimeout"], long_attrs.get("control")) == ("3600", "long-control"), (
        f"TimerStarted(long) attributes were {long_attrs!r}"
    )
    assert by_id[long_attrs["decisionTaskCompletedEventId"]]["eventType"] == "DecisionTaskCompleted", (
        "TimerStarted(long).decisionTaskCompletedEventId does not name a DecisionTaskCompleted event"
    )

    failed = [e["cancelTimerFailedEventAttributes"] for e in events if e["eventType"] == "CancelTimerFailed"]
    assert len(failed) == 1, f"expected one CancelTimerFailed, got {failed!r}"
    assert (failed[0]["timerId"], failed[0]["cause"]) == ("never-started", "TIMER_ID_UNKNOWN"), (
        f"CancelTimerFailed attributes were {failed[0]!r}"
    )
    assert failed[0]["decisionTaskCompletedEventId"] == long_attrs["decisionTaskCompletedEventId"], (
        "CancelTimerFailed and TimerStarted(long) came from the same decision but name different "
        "DecisionTaskCompleted events"
    )

    canceled = [e["timerCanceledEventAttributes"] for e in events if e["eventType"] == "TimerCanceled"]
    assert [c["timerId"] for c in canceled] == ["long"], f"TimerCanceled events were {canceled!r}"
    assert canceled[0]["startedEventId"] == started["long"]["eventId"], (
        "TimerCanceled.startedEventId does not point at TimerStarted(long)"
    )
    fired = [e["timerFiredEventAttributes"] for e in events if e["eventType"] == "TimerFired"]
    assert [f["timerId"] for f in fired] == ["short"], f"TimerFired events were {fired!r}"
    assert fired[0]["startedEventId"] == started["short"]["eventId"], (
        "TimerFired.startedEventId does not point at TimerStarted(short)"
    )
    status = swf.describe_workflow_execution(domain=domain, execution=execution)["executionInfo"]
    assert status.get("closeStatus") == "COMPLETED", f"execution closeStatus was {status.get('closeStatus')!r}"


def _next_decision(swf, domain: str, task_list: str, timeout_s: float = 120.0) -> dict[str, Any]:
    """The next decision task on ``task_list``, every history page merged into ``events``."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
        if resp.get("taskToken"):
            events = list(resp["events"])
            token = resp.get("nextPageToken")
            while token:
                page = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list},
                                                  nextPageToken=token)
                events.extend(page["events"])
                token = page.get("nextPageToken")
            resp["events"] = events
            return resp
    raise AssertionError(f"no decision task was delivered on the task list within {timeout_s:.0f}s")


def _history(swf, domain: str, execution: dict) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {"domain": domain, "execution": execution}
    while True:
        resp = swf.get_workflow_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextPageToken"):
            return events
        kwargs["nextPageToken"] = resp["nextPageToken"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


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
