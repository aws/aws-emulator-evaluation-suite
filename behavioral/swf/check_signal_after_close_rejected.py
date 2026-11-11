"""signal-after-close-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signal-after-close-rejected"
GROUP = "overly-permissive"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SignalWorkflowExecution against a workflow execution that has already closed
    is rejected with UnknownResourceFault rather than silently accepted; a signal to
    a still-open execution succeeds and is recorded in history."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)

    # Positive control: an OPEN execution.
    open_wf_id = ctx.unique_name("sim2real-swf-wf-open-")
    open_run_id = _start_workflow(ctx, domain, open_wf_id, wf_type, task_list)

    # Target: an execution we close before signaling it.
    closed_wf_id = ctx.unique_name("sim2real-swf-wf-closed-")
    closed_run_id = _start_workflow(ctx, domain, closed_wf_id, wf_type, task_list)
    swf.terminate_workflow_execution(domain=domain, workflowId=closed_wf_id, runId=closed_run_id, reason="close-for-test")
    _poll_until(
        lambda: swf.describe_workflow_execution(
            domain=domain, execution={"workflowId": closed_wf_id, "runId": closed_run_id}
        )["executionInfo"]["executionStatus"],
        lambda status: status == "CLOSED",
        timeout_s=30.0,
        interval_s=1.0,
    )

    code, message = _error(
        lambda: swf.signal_workflow_execution(
            domain=domain, workflowId=closed_wf_id, runId=closed_run_id, signalName="too-late"
        )
    )
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault signaling a closed execution, got {code!r}"
    expected = f"Unknown execution: WorkflowExecution=[workflowId={closed_wf_id}, runId={closed_run_id}]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    closed_events = _get_history(ctx, domain, closed_wf_id, closed_run_id)
    assert not any(e["eventType"] == "WorkflowExecutionSignaled" for e in closed_events), (
        "a signal was recorded in history against an already-closed execution"
    )

    swf.signal_workflow_execution(
        domain=domain, workflowId=open_wf_id, runId=open_run_id, signalName="on-time", input="hello"
    )
    open_events = _poll_until(
        lambda: _get_history(ctx, domain, open_wf_id, open_run_id),
        lambda evs: any(e["eventType"] == "WorkflowExecutionSignaled" for e in evs),
        timeout_s=30.0,
        interval_s=2.0,
    )
    signaled = next(e for e in open_events if e["eventType"] == "WorkflowExecutionSignaled")
    attrs = signaled["workflowExecutionSignaledEventAttributes"]
    assert attrs["signalName"] == "on-time", f"expected signalName 'on-time', got {attrs['signalName']!r}"
    assert attrs["input"] == "hello", f"expected input 'hello', got {attrs['input']!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected signal_workflow_execution to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
