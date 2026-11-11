"""execution-timeout-enforced-server-side."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execution-timeout-enforced-server-side"
GROUP = "server-side"
SERVICES = ["swf"]


# timing:real-time — workflow: 8 s https://docs.aws.amazon.com/amazonswf/latest/developerguide/swf-timeout-types.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A workflow execution started with a short executionStartToCloseTimeout is
    force-closed by the service itself (WorkflowExecutionTimedOut) once the timeout
    elapses, with no client action, and shows up as TIMED_OUT in the closed list."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    started_before = datetime.now(timezone.utc) - timedelta(minutes=1)
    run_id = _start_workflow(
        ctx, domain, workflow_id, wf_type, task_list, executionStartToCloseTimeout="8"
    )
    # Deliberately never poll or respond to any task for this execution.

    events = _poll_until(
        lambda: _get_history(ctx, domain, workflow_id, run_id),
        lambda evs: any(e["eventType"] == "WorkflowExecutionTimedOut" for e in evs),
        timeout_s=90.0,
        interval_s=3.0,
    )
    timeout_events = [e for e in events if e["eventType"] == "WorkflowExecutionTimedOut"]
    assert len(timeout_events) == 1, f"expected exactly one WorkflowExecutionTimedOut event, got {len(timeout_events)}"
    timedout = timeout_events[0]
    timeout_type = timedout["workflowExecutionTimedOutEventAttributes"]["timeoutType"]
    assert timeout_type == "START_TO_CLOSE", f"expected timeoutType START_TO_CLOSE, got {timeout_type!r}"

    started_event = next(e for e in events if e["eventType"] == "WorkflowExecutionStarted")
    elapsed_s = (timedout["eventTimestamp"] - started_event["eventTimestamp"]).total_seconds()
    assert elapsed_s >= 5, (
        f"timed out after only {elapsed_s:.1f}s against an 8s executionStartToCloseTimeout -- "
        "fired too early to be honoring the requested timeout"
    )

    desc = swf.describe_workflow_execution(domain=domain, execution={"workflowId": workflow_id, "runId": run_id})
    status = desc["executionInfo"]["executionStatus"]
    assert status == "CLOSED", f"expected executionStatus CLOSED, got {status!r}"
    close_status = desc["executionInfo"]["closeStatus"]
    assert close_status == "TIMED_OUT", f"expected closeStatus TIMED_OUT, got {close_status!r}"

    # ListClosedWorkflowExecutions allows at most one "exclusive" filter alongside the
    # required time filter (executionFilter/typeFilter/tagFilter/closeStatusFilter are
    # mutually exclusive) -- use executionFilter to scope to our workflow and check the
    # closeStatus on the returned info instead of also passing closeStatusFilter.
    closed = _poll_until(
        lambda: swf.list_closed_workflow_executions(
            domain=domain,
            startTimeFilter={"oldestDate": started_before},
            executionFilter={"workflowId": workflow_id},
        )["executionInfos"],
        lambda infos: any(
            info["execution"]["workflowId"] == workflow_id and info.get("closeStatus") == "TIMED_OUT"
            for info in infos
        ),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert any(
        info["execution"]["workflowId"] == workflow_id and info["closeStatus"] == "TIMED_OUT"
        for info in closed
    ), f"workflow {workflow_id} not visible as TIMED_OUT in ListClosedWorkflowExecutions: {closed!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
