"""cancel-timer-failed-then-complete-workflow-execution."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-timer-failed-then-complete-workflow-execution"
GROUP = "decisions"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CancelTimer(never-started) paired with CompleteWorkflowExecution in one decision task
    records CancelTimerFailed then CompleteWorkflowExecutionFailed(UNHANDLED_DECISION); the
    execution stays open with a new decision task scheduled.
    """
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
        {"decisionType": "CancelTimer", "cancelTimerDecisionAttributes": {"timerId": "never-started"}},
        {"decisionType": "CompleteWorkflowExecution",
         "completeWorkflowExecutionDecisionAttributes": {"result": "done"}},
    ])

    events = _history(swf, domain, execution)
    completed_ids = [e["eventId"] for e in events if e["eventType"] == "DecisionTaskCompleted"]
    assert len(completed_ids) == 1, f"expected one DecisionTaskCompleted, got eventIds {completed_ids!r}"
    decision_completed_id = completed_ids[0]

    failed = [e for e in events if e["eventType"] == "CancelTimerFailed"]
    assert len(failed) == 1, f"expected one CancelTimerFailed, got {failed!r}"
    failed_attrs = failed[0]["cancelTimerFailedEventAttributes"]
    assert (failed_attrs["timerId"], failed_attrs["cause"]) == ("never-started", "TIMER_ID_UNKNOWN"), (
        f"CancelTimerFailed attributes were {failed_attrs!r}"
    )
    assert failed_attrs["decisionTaskCompletedEventId"] == decision_completed_id, (
        f"CancelTimerFailed named decisionTaskCompletedEventId {failed_attrs['decisionTaskCompletedEventId']!r}, "
        f"not the decision's own {decision_completed_id!r}"
    )

    close_failed = [e for e in events if e["eventType"] == "CompleteWorkflowExecutionFailed"]
    assert len(close_failed) == 1, (
        f"expected one CompleteWorkflowExecutionFailed, got {close_failed!r}; "
        f"all events were {[(e['eventId'], e['eventType']) for e in events]!r}"
    )
    close_failed_attrs = close_failed[0]["completeWorkflowExecutionFailedEventAttributes"]
    assert close_failed_attrs["cause"] == "UNHANDLED_DECISION", (
        f"CompleteWorkflowExecutionFailed.cause was {close_failed_attrs['cause']!r}"
    )
    assert close_failed_attrs["decisionTaskCompletedEventId"] == decision_completed_id, (
        f"CompleteWorkflowExecutionFailed named decisionTaskCompletedEventId "
        f"{close_failed_attrs['decisionTaskCompletedEventId']!r}, not the decision's own {decision_completed_id!r}"
    )
    assert failed[0]["eventId"] < close_failed[0]["eventId"], (
        f"CancelTimerFailed (eventId {failed[0]['eventId']!r}) did not precede "
        f"CompleteWorkflowExecutionFailed (eventId {close_failed[0]['eventId']!r})"
    )

    info = swf.describe_workflow_execution(domain=domain, execution=execution)
    assert info["executionInfo"]["executionStatus"] == "OPEN", (
        f"executionStatus after the rejected close was {info['executionInfo']['executionStatus']!r}, "
        "expected the execution to stay open"
    )
    assert info["openCounts"]["openDecisionTasks"] == 1, (
        f"openDecisionTasks after the rejected close was {info['openCounts']['openDecisionTasks']!r}, "
        "expected a new decision task to be scheduled"
    )

    # Positive control: the same closing decision, sent alone, actually closes the execution.
    second = _next_decision(swf, domain, task_list)
    second_new = [e["eventType"] for e in second["events"] if e["eventId"] > decision_completed_id]
    assert second_new == [
        "CancelTimerFailed", "CompleteWorkflowExecutionFailed", "DecisionTaskScheduled", "DecisionTaskStarted",
    ], f"events after the rejected decision were {second_new!r}"
    swf.respond_decision_task_completed(taskToken=second["taskToken"], decisions=[
        {"decisionType": "CompleteWorkflowExecution",
         "completeWorkflowExecutionDecisionAttributes": {"result": "done"}},
    ])

    final_events = _history(swf, domain, execution)
    completed = [e for e in final_events if e["eventType"] == "WorkflowExecutionCompleted"]
    assert len(completed) == 1, (
        f"expected one WorkflowExecutionCompleted after the clean retry, got {completed!r}"
    )
    assert completed[0]["workflowExecutionCompletedEventAttributes"]["result"] == "done", (
        f"WorkflowExecutionCompleted.result was "
        f"{completed[0]['workflowExecutionCompletedEventAttributes']['result']!r}"
    )

    info = swf.describe_workflow_execution(domain=domain, execution=execution)
    assert info["executionInfo"]["executionStatus"] == "CLOSED", (
        f"executionStatus after the clean CompleteWorkflowExecution was "
        f"{info['executionInfo']['executionStatus']!r}"
    )
    assert info["executionInfo"].get("closeStatus") == "COMPLETED", (
        f"closeStatus after the clean CompleteWorkflowExecution was "
        f"{info['executionInfo'].get('closeStatus')!r}"
    )
    assert info["openCounts"]["openDecisionTasks"] == 0, (
        f"openDecisionTasks on a closed execution was {info['openCounts']['openDecisionTasks']!r}"
    )


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
