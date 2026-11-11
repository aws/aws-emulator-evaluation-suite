"""decision-task-start-to-close-timeout-reschedules."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "decision-task-start-to-close-timeout-reschedules"
GROUP = "visibility-timeout-ttl"
SERVICES = ["swf"]


# timing:real-time — workflow: 6 s https://docs.aws.amazon.com/amazonswf/latest/developerguide/swf-timeout-types.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An unanswered decision task times out START_TO_CLOSE between the configured timeout and 30 s after it,
    the DecisionTaskTimedOut names that task's startedEventId, and a new decision task with a new token is pollable."""
    ctx.client("swf")
    task_start_to_close_timeout_s = 6
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    wf_type = _register_workflow_type(
        ctx, domain, task_list, defaultTaskStartToCloseTimeout=str(task_start_to_close_timeout_s)
    )

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, task_list)

    dtask1 = _poll_decision_until_task(ctx, domain, task_list)
    assert dtask1["taskToken"], f"expected a decision task token, got {dtask1!r}"
    # Deliberately never respond to dtask1; wait for the server-side timeout.

    events = _poll_until(
        lambda: _get_history(ctx, domain, workflow_id, run_id),
        lambda evs: any(e["eventType"] == "DecisionTaskTimedOut" for e in evs),
        timeout_s=90.0,
        interval_s=3.0,
    )
    timedout_event = next(e for e in events if e["eventType"] == "DecisionTaskTimedOut")
    timedout_attrs = timedout_event["decisionTaskTimedOutEventAttributes"]
    assert timedout_attrs["timeoutType"] == "START_TO_CLOSE", (
        f"expected timeoutType START_TO_CLOSE, got {timedout_attrs['timeoutType']!r}"
    )
    assert timedout_attrs["startedEventId"] == dtask1["startedEventId"], (
        f"DecisionTaskTimedOut is tied to startedEventId {timedout_attrs['startedEventId']!r}, "
        f"not the decision task under test ({dtask1['startedEventId']!r})"
    )

    started_event = next(e for e in events if e["eventId"] == dtask1["startedEventId"])
    elapsed_s = (timedout_event["eventTimestamp"] - started_event["eventTimestamp"]).total_seconds()
    assert task_start_to_close_timeout_s <= elapsed_s < task_start_to_close_timeout_s + 30, (
        f"expected the timeout to fire between {task_start_to_close_timeout_s}s and "
        f"{task_start_to_close_timeout_s + 30}s after the task started, took {elapsed_s}s"
    )

    dtask2 = _poll_decision_until_task(ctx, domain, task_list)
    assert dtask2["taskToken"], f"expected a rescheduled decision task token, got {dtask2!r}"
    assert dtask2["taskToken"] != dtask1["taskToken"], "rescheduled decision task reused the timed-out task's token"
    assert dtask2["startedEventId"] != dtask1["startedEventId"], (
        "rescheduled decision task reused the timed-out task's startedEventId"
    )


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
