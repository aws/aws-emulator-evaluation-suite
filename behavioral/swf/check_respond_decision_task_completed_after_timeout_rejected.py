"""respond-decision-task-completed-after-timeout-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "respond-decision-task-completed-after-timeout-rejected"
GROUP = "overly-permissive"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a decision task times out and is reassigned, RespondDecisionTaskCompleted with the stale token fails with
    UnknownResourceFault and its exact message and adds no events; the fresh token then completes the workflow."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    wf_name = ctx.unique_name("sim2real-swf-wft-")
    version = "1.0"
    swf.register_workflow_type(
        domain=domain,
        name=wf_name,
        version=version,
        defaultTaskList={"name": task_list},
        defaultTaskStartToCloseTimeout="6",
        defaultExecutionStartToCloseTimeout="300",
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": version}))

    run_id = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_name, "version": version},
        taskList={"name": task_list},
        taskStartToCloseTimeout="6",
    )["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}
    ctx.on_cleanup(
        lambda: _safe(lambda: swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id))
    )

    stale = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
    stale_token = stale.get("taskToken")
    assert stale_token, "no initial decision task was scheduled"
    # Deliberately never respond to `stale_token` -- let its start-to-close timeout elapse.

    timed_out = _poll_until(
        lambda: _find_event(swf, domain, execution, "DecisionTaskTimedOut"),
        lambda evt: evt is not None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert timed_out is not None, "DecisionTaskTimedOut event never appeared"

    fresh = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
    fresh_token = fresh.get("taskToken")
    assert fresh_token, "no replacement decision task was made available after the timeout"
    assert fresh_token != stale_token, f"expected a fresh token distinct from the stale one, got {fresh_token!r}"

    history_before = swf.get_workflow_execution_history(domain=domain, execution=execution)
    events_before = [e["eventType"] for e in history_before["events"]]

    # Break exactly one thing: respond using the stale, already-superseded token.
    code, message = _error(
        lambda: swf.respond_decision_task_completed(
            taskToken=stale_token,
            decisions=[
                {
                    "decisionType": "CompleteWorkflowExecution",
                    "completeWorkflowExecutionDecisionAttributes": {"result": "late"},
                }
            ],
        )
    )
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault, got {code!r}"
    started = next(e for e in history_before["events"] if e["eventId"] == stale["startedEventId"])
    scheduled_id = started["decisionTaskStartedEventAttributes"]["scheduledEventId"]
    expected = f"Unknown decision task, scheduledEventId = {scheduled_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no new history events were recorded and the workflow is still open.
    history_after = swf.get_workflow_execution_history(domain=domain, execution=execution)
    events_after = [e["eventType"] for e in history_after["events"]]
    assert events_after == events_before, "the stale completion produced extra history events"
    described = swf.describe_workflow_execution(domain=domain, execution=execution)
    status = described["executionInfo"]["executionStatus"]
    assert status == "OPEN", f"expected OPEN after the stale-token completion was rejected, got {status!r}"

    # Positive control: the fresh, reassigned token completes the decision task normally.
    swf.respond_decision_task_completed(
        taskToken=fresh_token,
        decisions=[
            {
                "decisionType": "CompleteWorkflowExecution",
                "completeWorkflowExecutionDecisionAttributes": {"result": "done"},
            }
        ],
    )
    described_after = swf.describe_workflow_execution(domain=domain, execution=execution)
    status_after = described_after["executionInfo"]["executionStatus"]
    assert status_after == "CLOSED", f"expected CLOSED after the fresh token completed, got {status_after!r}"
    close_status = described_after["executionInfo"]["closeStatus"]
    assert close_status == "COMPLETED", f"expected COMPLETED close status, got {close_status!r}"


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


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the stale-token call to be rejected, but it SUCCEEDED and returned {result!r}")


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
