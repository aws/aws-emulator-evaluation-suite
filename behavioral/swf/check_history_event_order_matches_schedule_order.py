"""history-event-order-matches-schedule-order."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "history-event-order-matches-schedule-order"
GROUP = "ordering"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """When a decision closes by scheduling multiple activities in one response, the
    resulting ActivityTaskScheduled events appear in history in the same order they
    were listed in the decision list (not, e.g., alphabetical or reversed)."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)
    act_type = _register_activity_type(ctx, domain, task_list)

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, task_list)

    dtask = _poll_decision_until_task(ctx, domain, task_list)

    # Deliberately non-alphabetical scheduling order to prove history preserves it verbatim.
    ordered_ids = ["act-charlie", "act-alpha", "act-bravo"]
    swf.respond_decision_task_completed(
        taskToken=dtask["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_type[0], "version": act_type[1]},
                    "activityId": activity_id,
                    "taskList": {"name": task_list},
                    "scheduleToStartTimeout": "60",
                    "scheduleToCloseTimeout": "120",
                    "startToCloseTimeout": "60",
                    "heartbeatTimeout": "60",
                },
            }
            for activity_id in ordered_ids
        ],
    )

    events = _poll_until(
        lambda: _get_history(ctx, domain, workflow_id, run_id),
        lambda evs: sum(1 for e in evs if e["eventType"] == "ActivityTaskScheduled") >= 3,
        timeout_s=30.0,
        interval_s=2.0,
    )
    scheduled = [e for e in events if e["eventType"] == "ActivityTaskScheduled"]
    scheduled.sort(key=lambda e: e["eventId"])
    observed_ids = [e["activityTaskScheduledEventAttributes"]["activityId"] for e in scheduled]
    assert observed_ids == ordered_ids, f"expected {ordered_ids}, got {observed_ids}"


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
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": name, "version": version}))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
