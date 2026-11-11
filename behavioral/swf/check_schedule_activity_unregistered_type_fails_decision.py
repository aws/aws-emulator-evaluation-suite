"""schedule-activity-unregistered-type-fails-decision."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-activity-unregistered-type-fails-decision"
GROUP = "decision-failures"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """ScheduleActivityTask for an unregistered activity type records ScheduleActivityTaskFailed
    ACTIVITY_TYPE_DOES_NOT_EXIST with the decision's ids and schedules nothing; a registered type schedules
    and is delivered."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-behav-swf-tl-")
    activity_list = ctx.unique_name("sim2real-behav-swf-atl-")
    wf_name = ctx.unique_name("sim2real-behav-swf-wft-")
    swf.register_workflow_type(
        domain=domain, name=wf_name, version="1.0",
        defaultTaskStartToCloseTimeout="60", defaultExecutionStartToCloseTimeout="600",
        defaultTaskList={"name": task_list}, defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": "1.0"}))
    act_name = ctx.unique_name("sim2real-behav-swf-act-")
    swf.register_activity_type(
        domain=domain, name=act_name, version="1.0",
        defaultTaskStartToCloseTimeout="60", defaultTaskHeartbeatTimeout="NONE",
        defaultTaskScheduleToStartTimeout="300", defaultTaskScheduleToCloseTimeout="360",
        defaultTaskList={"name": activity_list},
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": act_name, "version": "1.0"}))
    missing = {"name": ctx.unique_name("sim2real-behav-swf-noact-"), "version": "1.0"}
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
        {"decisionType": "ScheduleActivityTask", "scheduleActivityTaskDecisionAttributes": {
            "activityId": "bad-1", "activityType": missing}},
    ])

    second = _next_decision(swf, domain, task_list)
    fresh = [e for e in second["events"] if e["eventId"] > second["previousStartedEventId"]]
    fresh_types = [e["eventType"] for e in fresh]
    assert "ScheduleActivityTaskFailed" in fresh_types, (
        f"the refused ScheduleActivityTask did not reach the decider; new events were {fresh_types!r}"
    )
    assert "ActivityTaskScheduled" not in fresh_types, (
        f"an activity was scheduled for a type that does not exist: {fresh_types!r}"
    )
    failed = next(e for e in fresh if e["eventType"] == "ScheduleActivityTaskFailed")
    attrs = failed["scheduleActivityTaskFailedEventAttributes"]
    assert (attrs["cause"], attrs["activityId"], attrs["activityType"]) == (
        "ACTIVITY_TYPE_DOES_NOT_EXIST", "bad-1", missing), (
        f"ScheduleActivityTaskFailed attributes were cause={attrs.get('cause')!r} "
        f"activityId={attrs.get('activityId')!r}, type matches={attrs.get('activityType') == missing}"
    )
    by_id = {e["eventId"]: e for e in second["events"]}
    assert by_id[attrs["decisionTaskCompletedEventId"]]["eventType"] == "DecisionTaskCompleted", (
        "ScheduleActivityTaskFailed.decisionTaskCompletedEventId does not name a DecisionTaskCompleted"
    )
    after_failure = [e["eventType"] for e in second["events"] if e["eventId"] > failed["eventId"]]
    assert after_failure[:1] == ["DecisionTaskScheduled"], (
        f"the failed decision was not followed by a new DecisionTaskScheduled: {after_failure!r}"
    )
    counts = swf.describe_workflow_execution(domain=domain, execution=execution)["openCounts"]
    assert counts["openActivityTasks"] == 0, (
        f"openActivityTasks after the refused schedule was {counts['openActivityTasks']!r}"
    )

    # Positive control: the same decision shape with a registered type schedules and delivers.
    swf.respond_decision_task_completed(taskToken=second["taskToken"], decisions=[
        {"decisionType": "ScheduleActivityTask", "scheduleActivityTaskDecisionAttributes": {
            "activityId": "good-1", "activityType": {"name": act_name, "version": "1.0"}}},
    ])
    activity = None
    deadline = time.monotonic() + 120.0
    while activity is None and time.monotonic() < deadline:
        resp = swf.poll_for_activity_task(domain=domain, taskList={"name": activity_list})
        if resp.get("taskToken"):
            activity = resp
    assert activity is not None, "the registered activity was never delivered to the activity poller"
    assert (activity["activityId"], activity["activityType"]) == (
        "good-1", {"name": act_name, "version": "1.0"}), (
        f"delivered activity was {activity.get('activityId')!r}"
    )
    swf.respond_activity_task_completed(taskToken=activity["taskToken"], result="ok")

    events = _history(swf, domain, execution)
    scheduled = [e["activityTaskScheduledEventAttributes"]["activityId"]
                 for e in events if e["eventType"] == "ActivityTaskScheduled"]
    assert scheduled == ["good-1"], f"ActivityTaskScheduled activity ids were {scheduled!r}"
    failures = [e["scheduleActivityTaskFailedEventAttributes"]["activityId"]
                for e in events if e["eventType"] == "ScheduleActivityTaskFailed"]
    assert failures == ["bad-1"], f"ScheduleActivityTaskFailed activity ids were {failures!r}"


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
