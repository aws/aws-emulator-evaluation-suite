"""decision-task-timeout-server-enforced."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "decision-task-timeout-server-enforced"
GROUP = "server-side"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A started, unanswered decision task gets DecisionTaskTimedOut (START_TO_CLOSE, linked to its scheduled and
    started events) and a later DecisionTaskScheduled in history with no further client call."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    wf_type = _register_workflow_type(ctx, domain, ctx.unique_name("sim2real-swf-wft-"))
    task_list = ctx.unique_name("sim2real-swf-tl-")
    workflow_id = ctx.unique_name("sim2real-swf-wf-")

    run_id = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType=wf_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout="300",
        taskStartToCloseTimeout="6",
        childPolicy="TERMINATE",
        tagList=["sim2real"],
    )["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}
    ctx.on_cleanup(
        lambda: _safe(lambda: swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id))
    )

    task = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
    assert task.get("taskToken"), "no decision task was scheduled at workflow start"
    started_event_id = task["startedEventId"]

    scheduled_evt = _find_event(swf, domain, execution, "DecisionTaskScheduled")
    started_evt = _find_event(swf, domain, execution, "DecisionTaskStarted")
    assert scheduled_evt is not None, "no DecisionTaskScheduled event was recorded in the history"
    assert started_evt is not None, "no DecisionTaskStarted event was recorded in the history"
    assert started_evt["eventId"] == started_event_id, (
        f"expected DecisionTaskStarted eventId {started_event_id}, got {started_evt['eventId']}"
    )

    # Deliberately never poll or respond again -- only passively observe the history while
    # the taskStartToCloseTimeout (6s) elapses server-side.
    timed_out = _poll_until(
        lambda: _find_event(swf, domain, execution, "DecisionTaskTimedOut"),
        lambda evt: evt is not None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert timed_out is not None, "DecisionTaskTimedOut was never recorded without further client action"
    to_attrs = timed_out["decisionTaskTimedOutEventAttributes"]
    assert to_attrs["timeoutType"] == "START_TO_CLOSE", (
        f"expected timeoutType START_TO_CLOSE, got {to_attrs['timeoutType']}"
    )
    assert to_attrs["scheduledEventId"] == scheduled_evt["eventId"], (
        f"expected scheduledEventId {scheduled_evt['eventId']}, got {to_attrs['scheduledEventId']}"
    )
    assert to_attrs["startedEventId"] == started_evt["eventId"], (
        f"expected startedEventId {started_evt['eventId']}, got {to_attrs['startedEventId']}"
    )

    # The service must also have rescheduled a fresh decision task on its own, with a
    # strictly higher eventId than the timeout event, again with no client action.
    history = swf.get_workflow_execution_history(domain=domain, execution=execution)["events"]
    scheduled_event_ids = [
        e["eventId"] for e in history if e["eventType"] == "DecisionTaskScheduled"
    ]
    assert len(scheduled_event_ids) >= 2, "no replacement DecisionTaskScheduled event was recorded after the timeout"
    assert max(scheduled_event_ids) > timed_out["eventId"], "the rescheduled decision task did not follow the timeout event"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DomainDeprecatedFault",
            "TypeDeprecatedFault",
            "UnknownResourceFault",
        ):
            raise


def _register_workflow_type(ctx, domain: str, name: str, version: str = "1.0") -> dict:
    swf = ctx.client("swf")
    swf.register_workflow_type(domain=domain, name=name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": name, "version": version}))
    return {"name": name, "version": version}


def _find_event(swf, domain, execution, event_type):
    events = swf.get_workflow_execution_history(domain=domain, execution=execution)["events"]
    for evt in events:
        if evt["eventType"] == event_type:
            return evt
    return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


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
