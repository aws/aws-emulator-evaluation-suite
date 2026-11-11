"""cancel-request-triggers-server-emitted-event."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-request-triggers-server-emitted-event"
GROUP = "server-side"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RequestCancelWorkflowExecution causes the service itself to append a
    WorkflowExecutionCancelRequested history event and deliver a corresponding new
    decision task, without any client-side history mutation call."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, task_list)

    # Drain the initial decision task with no decisions, leaving no task outstanding.
    dtask1 = _poll_decision_until_task(ctx, domain, task_list)
    swf.respond_decision_task_completed(taskToken=dtask1["taskToken"], decisions=[])

    swf.request_cancel_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id)

    _poll_until(
        lambda: swf.describe_workflow_execution(
            domain=domain, execution={"workflowId": workflow_id, "runId": run_id}
        )["executionInfo"]["cancelRequested"],
        lambda flag: flag is True,
        timeout_s=30.0,
        interval_s=2.0,
    )

    dtask2 = _poll_decision_until_task(ctx, domain, task_list)
    dtask2_types = [e["eventType"] for e in dtask2["events"]]
    assert "WorkflowExecutionCancelRequested" in dtask2_types, (
        f"expected WorkflowExecutionCancelRequested in the decision task's events, got {dtask2_types}"
    )

    history_events = _get_history(ctx, domain, workflow_id, run_id)
    history_types = [e["eventType"] for e in history_events]
    assert "WorkflowExecutionCancelRequested" in history_types, (
        f"expected WorkflowExecutionCancelRequested in workflow history, got {history_types}"
    )


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


def _poll_decision_until_task(ctx, domain: str, task_list: str, timeout_s: float = 90.0) -> dict[str, Any]:
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
        if resp.get("taskToken"):
            return resp
    raise AssertionError(f"no decision task delivered on {task_list!r} within {timeout_s}s")


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
