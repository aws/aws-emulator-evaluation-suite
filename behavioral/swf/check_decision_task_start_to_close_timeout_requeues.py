"""decision-task-start-to-close-timeout-requeues."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "decision-task-start-to-close-timeout-requeues"
GROUP = "visibility-timeout-ttl"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A decision task left unresponded past its taskStartToCloseTimeout is marked
    DecisionTaskTimedOut by the service and becomes available for redelivery to a
    subsequent poller, with no client-side action required."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-dtt-tl-")
    workflow_id = ctx.unique_name("sim2real-swf-dtt-wf-")
    wf_name = ctx.unique_name("sim2real-swf-dtt-wftype-")
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
        lambda: _safe(
            lambda: swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id)
        )
    )

    first_task = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
    assert first_task.get("taskToken"), "no decision task was scheduled at workflow start"
    # Deliberately never respond -- let the taskStartToCloseTimeout (6s) elapse.

    timed_out = _poll_until(
        lambda: _find_event(swf, domain, execution, "DecisionTaskTimedOut"),
        lambda evt: evt is not None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert timed_out is not None, "DecisionTaskTimedOut event never appeared"
    attrs = timed_out["decisionTaskTimedOutEventAttributes"]
    assert attrs["timeoutType"] == "START_TO_CLOSE", f"expected START_TO_CLOSE, got {attrs['timeoutType']}"

    # The timed-out task must be redelivered to a subsequent poller -- as a genuinely new
    # decision task, not the same one echoed back.
    second_task = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
    assert second_task.get("taskToken"), "no replacement decision task was made available for redelivery"
    assert second_task["taskToken"] != first_task["taskToken"], (
        f"redelivered task token matches the original: {second_task['taskToken']!r}"
    )
    assert second_task["startedEventId"] != first_task["startedEventId"], (
        "redelivered task shares the original startedEventId -- no new decision task was actually started"
    )
    swf.respond_decision_task_completed(
        taskToken=second_task["taskToken"],
        decisions=[
            {
                "decisionType": "CompleteWorkflowExecution",
                "completeWorkflowExecutionDecisionAttributes": {"result": "done"},
            }
        ],
    )

    # Independent read at the destination: the redelivered task is a live, valid decision
    # task -- responding to it actually closes the execution.
    described = swf.describe_workflow_execution(domain=domain, execution=execution)
    assert described["executionInfo"]["executionStatus"] == "CLOSED", (
        f"expected CLOSED after completing the redelivered task, got {described['executionInfo']['executionStatus']!r}"
    )
    assert described["executionInfo"]["closeStatus"] == "COMPLETED", (
        f"expected COMPLETED, got {described['executionInfo'].get('closeStatus')!r}"
    )


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
