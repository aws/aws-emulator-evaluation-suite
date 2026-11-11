"""respond-activity-task-canceled-unknown-token-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "respond-activity-task-canceled-unknown-token-error"
GROUP = "error-semantics"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RespondActivityTaskCanceled with an open activity task's token records one ActivityTaskCanceled; reusing the
    token fails with UnknownResourceFault and its exact message and adds no second ActivityTaskCanceled."""
    setup = _setup_activity_task(ctx)
    swf = setup["swf"]

    # positive control: the real, open activity task's taskToken is accepted
    swf.respond_activity_task_canceled(taskToken=setup["task_token"], details="stopping")
    history_after = swf.get_workflow_execution_history(
        domain=setup["domain"],
        execution={"workflowId": setup["workflow_id"], "runId": setup["run_id"]},
    )
    event_types_after = [e["eventType"] for e in history_after["events"]]
    assert event_types_after.count("ActivityTaskCanceled") == 1, event_types_after

    # reusing the same stale taskToken must be rejected with UnknownResourceFault,
    # and must not add a second ActivityTaskCanceled event
    code, message = _error(lambda: swf.respond_activity_task_canceled(taskToken=setup["task_token"]))
    assert code == "UnknownResourceFault", f"GOT={code!r}"
    scheduled_id = _scheduled_event_id(history_after["events"], setup["started_event_id"])
    expected = f"Unknown activity, scheduledEventId = {scheduled_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    history_final = swf.get_workflow_execution_history(
        domain=setup["domain"],
        execution={"workflowId": setup["workflow_id"], "runId": setup["run_id"]},
    )
    event_types_final = [e["eventType"] for e in history_final["events"]]
    assert event_types_final.count("ActivityTaskCanceled") == 1, event_types_final


def _setup_activity_task(ctx) -> dict:
    """Registers a workflow type/activity type in the shared domain, starts an execution, drives it through
    a decision that schedules an activity task, and polls that activity task to get a real,
    open taskToken."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    wf_task_list = ctx.unique_name("sim2real-behav-wftl-")
    act_task_list = ctx.unique_name("sim2real-behav-acttl-")
    wf_name = ctx.unique_name("sim2real-behav-wftype-")
    act_name = ctx.unique_name("sim2real-behav-acttype-")
    version = "1.0"

    swf.register_workflow_type(domain=domain, name=wf_name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": version}))
    swf.register_activity_type(domain=domain, name=act_name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": act_name, "version": version}))

    workflow_id = ctx.unique_name("sim2real-behav-wfid-")
    started = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_name, "version": version},
        taskList={"name": wf_task_list},
        executionStartToCloseTimeout="120",
        taskStartToCloseTimeout="60",
        childPolicy="TERMINATE",
    )
    run_id = started["runId"]
    ctx.on_cleanup(lambda: _terminate_quiet(swf, domain, workflow_id))

    decision_task = swf.poll_for_decision_task(domain=domain, taskList={"name": wf_task_list})
    assert decision_task.get("taskToken"), "expected an immediately available decision task"

    swf.respond_decision_task_completed(
        taskToken=decision_task["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_name, "version": version},
                    "activityId": ctx.unique_name("sim2real-behav-actid-"),
                    "taskList": {"name": act_task_list},
                    "scheduleToCloseTimeout": "60",
                    "scheduleToStartTimeout": "30",
                    "startToCloseTimeout": "30",
                    "heartbeatTimeout": "30",
                },
            }
        ],
    )

    activity_task = swf.poll_for_activity_task(domain=domain, taskList={"name": act_task_list})
    assert activity_task.get("taskToken"), "expected an immediately available activity task"

    return {
        "swf": swf,
        "domain": domain,
        "workflow_id": workflow_id,
        "run_id": run_id,
        "task_token": activity_task["taskToken"],
        "started_event_id": activity_task["startedEventId"],
    }


def _terminate_quiet(swf, domain, workflow_id):
    try:
        swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


def _scheduled_event_id(events, started_event_id):
    """The scheduledEventId of the ActivityTaskStarted event the polled task carries."""
    started = next(e for e in events if e["eventId"] == started_event_id)
    return started["activityTaskStartedEventAttributes"]["scheduledEventId"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a request real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected UnknownResourceFault but the call SUCCEEDED: {result!r}")


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
