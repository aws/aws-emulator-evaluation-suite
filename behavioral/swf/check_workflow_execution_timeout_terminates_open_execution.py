"""workflow-execution-timeout-terminates-open-execution."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workflow-execution-timeout-terminates-open-execution"
GROUP = "visibility-timeout-ttl"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An open execution whose executionStartToCloseTimeout elapses is force-closed
    as TIMED_OUT by the service itself -- no decider action, no client call -- and
    the closed-execution visibility APIs reflect it."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-wft-tl-")
    workflow_id = ctx.unique_name("sim2real-swf-wft-wf-")
    wf_name = ctx.unique_name("sim2real-swf-wft-wftype-")
    version = "1.0"
    swf.register_workflow_type(
        domain=domain,
        name=wf_name,
        version=version,
        defaultTaskList={"name": task_list},
        defaultTaskStartToCloseTimeout="NONE",
        defaultExecutionStartToCloseTimeout="300",
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": version}))

    before_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    run_id = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_name, "version": version},
        taskList={"name": task_list},
        executionStartToCloseTimeout="8",
        taskStartToCloseTimeout="NONE",
        childPolicy="TERMINATE",
    )["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}
    # Leave the execution completely unattended: never poll for or respond to any
    # decision task -- the ONLY thing that can close it is the service-side timeout.
    ctx.on_cleanup(
        lambda: _safe(
            lambda: swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id)
        )
    )

    described = _poll_until(
        lambda: swf.describe_workflow_execution(domain=domain, execution=execution),
        lambda resp: resp["executionInfo"]["executionStatus"] == "CLOSED",
        timeout_s=90.0,
        interval_s=3.0,
    )
    info = described["executionInfo"]
    assert info["closeStatus"] == "TIMED_OUT", f"expected TIMED_OUT, got {info.get('closeStatus')}"

    history = swf.get_workflow_execution_history(domain=domain, execution=execution)["events"]
    timeout_events = [e for e in history if e["eventType"] == "WorkflowExecutionTimedOut"]
    assert len(timeout_events) == 1, f"expected exactly one WorkflowExecutionTimedOut event, got {len(timeout_events)}"
    timeout_type = timeout_events[0]["workflowExecutionTimedOutEventAttributes"]["timeoutType"]
    assert timeout_type == "START_TO_CLOSE", f"expected timeoutType START_TO_CLOSE, got {timeout_type}"

    after_close = datetime.now(timezone.utc) + timedelta(minutes=1)
    closed = swf.list_closed_workflow_executions(
        domain=domain,
        closeTimeFilter={"oldestDate": before_start, "latestDate": after_close},
        executionFilter={"workflowId": workflow_id},
    )["executionInfos"]
    matching = [e for e in closed if e["execution"]["runId"] == run_id]
    assert len(matching) == 1, f"expected the execution to appear exactly once in ListClosedWorkflowExecutions, got {len(matching)}"
    assert matching[0]["executionStatus"] == "CLOSED", f"expected CLOSED, got {matching[0]['executionStatus']}"
    assert matching[0]["closeStatus"] == "TIMED_OUT", f"expected TIMED_OUT, got {matching[0]['closeStatus']}"


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={value!r})")
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
