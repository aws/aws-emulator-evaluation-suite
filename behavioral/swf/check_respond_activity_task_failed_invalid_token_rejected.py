"""respond-activity-task-failed-invalid-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "respond-activity-task-failed-invalid-token-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RespondActivityTaskFailed with the token of an already completed activity task fails with UnknownResourceFault
    and its exact message and records no ActivityTaskFailed; a second activity task is failed with its own token."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    task_list = {"name": ctx.unique_name("sim2real-swf-tl-")}
    wf_name = ctx.unique_name("sim2real-swf-wf-")
    act_name = ctx.unique_name("sim2real-swf-act-")
    version = "1.0"

    swf.register_workflow_type(
        domain=domain,
        name=wf_name,
        version=version,
        defaultTaskList=task_list,
        defaultTaskStartToCloseTimeout="60",
        defaultExecutionStartToCloseTimeout="180",
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": version}))

    swf.register_activity_type(
        domain=domain,
        name=act_name,
        version=version,
        defaultTaskList=task_list,
        defaultTaskHeartbeatTimeout="60",
        defaultTaskScheduleToStartTimeout="60",
        defaultTaskScheduleToCloseTimeout="120",
        defaultTaskStartToCloseTimeout="60",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": act_name, "version": version}))

    workflow_id = ctx.unique_name("sim2real-swf-exec-")
    start = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_name, "version": version},
        taskList=task_list,
    )
    run_id = start["runId"]
    ctx.on_cleanup(lambda: _safe(lambda: swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id)))

    decision_task = _poll_until_task(lambda: swf.poll_for_decision_task(domain=domain, taskList=task_list))
    assert decision_task.get("taskToken"), "expected a decision task token, got none"

    first_activity_id = ctx.unique_name("sim2real-swf-actid-")
    swf.respond_decision_task_completed(
        taskToken=decision_task["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_name, "version": version},
                    "activityId": first_activity_id,
                    "taskList": task_list,
                },
            }
        ],
    )

    activity_task = _poll_until_task(lambda: swf.poll_for_activity_task(domain=domain, taskList=task_list))
    real_token = activity_task.get("taskToken")
    assert real_token, "expected a task token on the first activity task, got none"

    # Consume the real token via a legitimate completion, so it is a well-formed but no-longer-valid
    # (already-closed) task token. This is a more faithful "unknown token" probe than corrupting bytes,
    # since corrupting the opaque token's internal structure can trip generic input validation instead
    # of the resource-lookup path we're targeting here.
    swf.respond_activity_task_completed(taskToken=real_token, result="done")

    code, message = _error(lambda: swf.respond_activity_task_failed(taskToken=real_token, reason="bogus"))
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault for a stale taskToken, got {code!r}"

    # effect absent: the execution's activity task is still recorded as completed (not failed) --
    # the stale-token RespondActivityTaskFailed call must not have appended a new terminal event
    history = swf.get_workflow_execution_history(domain=domain, execution={"workflowId": workflow_id, "runId": run_id})
    started = next(e for e in history["events"] if e["eventId"] == activity_task["startedEventId"])
    scheduled_id = started["activityTaskStartedEventAttributes"]["scheduledEventId"]
    expected = f"Unknown activity, scheduledEventId = {scheduled_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert any(e["eventType"] == "ActivityTaskCompleted" for e in history["events"]), (
        "expected an ActivityTaskCompleted event from the legitimate completion, found none"
    )
    assert not any(e["eventType"] == "ActivityTaskFailed" for e in history["events"]), (
        "the stale-token RespondActivityTaskFailed call must not append an ActivityTaskFailed event"
    )

    # Positive control: RespondActivityTaskFailed is not universally refused -- a second, freshly
    # scheduled activity task on the SAME execution can be failed normally with its own valid token.
    # Without this leg, the stale-token rejection above is indistinguishable from a target that
    # rejects every RespondActivityTaskFailed call regardless of token validity.
    decision_task_2 = _poll_until_task(lambda: swf.poll_for_decision_task(domain=domain, taskList=task_list))
    assert decision_task_2.get("taskToken"), "expected a second decision task token, got none"

    second_activity_id = ctx.unique_name("sim2real-swf-actid-")
    swf.respond_decision_task_completed(
        taskToken=decision_task_2["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_name, "version": version},
                    "activityId": second_activity_id,
                    "taskList": task_list,
                },
            }
        ],
    )

    second_activity_task = _poll_until_task(lambda: swf.poll_for_activity_task(domain=domain, taskList=task_list))
    second_token = second_activity_task.get("taskToken")
    assert second_token, "expected a task token on the second activity task, got none"

    swf.respond_activity_task_failed(taskToken=second_token, reason="deliberate-control-failure")

    final_events = swf.get_workflow_execution_history(
        domain=domain, execution={"workflowId": workflow_id, "runId": run_id}
    )["events"]
    failed_events = [e for e in final_events if e["eventType"] == "ActivityTaskFailed"]
    assert len(failed_events) == 1, f"expected exactly one ActivityTaskFailed event, found {len(failed_events)}"
    scheduled = next(
        e for e in final_events if e["eventId"] == failed_events[0]["activityTaskFailedEventAttributes"]["scheduledEventId"]
    )
    actual_activity_id = scheduled["activityTaskScheduledEventAttributes"]["activityId"]
    assert actual_activity_id == second_activity_id, (
        f"expected the ActivityTaskFailed event to trace back to {second_activity_id!r}, got {actual_activity_id!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DomainDeprecatedFault",
            "TypeDeprecatedFault",
            "UnknownResourceFault",
        ):
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_task(poll_fn, attempts=3):
    """SWF's Poll* calls are themselves a server-side long poll (up to 60s); a handful of retries
    is enough since a task is already scheduled by the time we start polling."""
    for _ in range(attempts):
        result = poll_fn()
        if result.get("taskToken"):
            return result
    raise AssertionError("no task became available via long-poll within the retry budget")


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
