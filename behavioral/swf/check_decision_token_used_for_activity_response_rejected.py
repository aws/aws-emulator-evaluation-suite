"""decision-token-used-for-activity-response-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decision-token-used-for-activity-response-rejected"
GROUP = "ordering"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Passing a decision taskToken to RespondActivityTaskCompleted is rejected as an unknown token."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    wf_type = _register_workflow_type(ctx, domain, ctx.unique_name("sim2real-swf-wft-"))
    act_type = _register_activity_type(ctx, domain, ctx.unique_name("sim2real-swf-act-"))
    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    decision_tl = ctx.unique_name("sim2real-swf-dtl-")
    activity_tl = ctx.unique_name("sim2real-swf-atl-")

    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, decision_tl)
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, workflow_id))
    execution = {"workflowId": workflow_id, "runId": run_id}

    decision = swf.poll_for_decision_task(domain=domain, taskList={"name": decision_tl})
    assert decision.get("taskToken"), f"expected a decision taskToken, got {decision!r}"
    decision_token = decision["taskToken"]
    swf.respond_decision_task_completed(
        taskToken=decision_token,
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": act_type,
                    "activityId": "act-1",
                    "taskList": {"name": activity_tl},
                    "scheduleToCloseTimeout": "60",
                    "scheduleToStartTimeout": "60",
                    "startToCloseTimeout": "60",
                    "heartbeatTimeout": "60",
                },
            }
        ],
    )

    activity = swf.poll_for_activity_task(domain=domain, taskList={"name": activity_tl})
    assert activity.get("taskToken"), f"expected an activity taskToken, got {activity!r}"
    activity_token = activity["taskToken"]

    # Break exactly one thing: use the (already-consumed) decision token, of the wrong
    # token type entirely, on an activity-response operation.
    code, message = _error(
        lambda: swf.respond_activity_task_completed(taskToken=decision_token, result="wrong-token")
    )
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault, got {code!r}"

    # Effect absent: the activity is still pending -- no ActivityTaskCompleted was recorded.
    history = swf.get_workflow_execution_history(domain=domain, execution=execution)
    completed_types = [e["eventType"] for e in history["events"] if e["eventType"] == "ActivityTaskCompleted"]
    assert completed_types == [], "activity was completed despite the mismatched token"
    decision_started = next(e for e in history["events"] if e["eventId"] == decision["startedEventId"])
    decision_scheduled_id = decision_started["decisionTaskStartedEventAttributes"]["scheduledEventId"]
    expected_message = f"Unknown activity, scheduledEventId = {decision_scheduled_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the real activity token still works.
    swf.respond_activity_task_completed(taskToken=activity_token, result="ok")
    history2 = swf.get_workflow_execution_history(domain=domain, execution=execution)
    completed = [e for e in history2["events"] if e["eventType"] == "ActivityTaskCompleted"]
    assert len(completed) == 1, f"expected exactly 1 ActivityTaskCompleted event, got {len(completed)}"
    actual_result = completed[0]["activityTaskCompletedEventAttributes"]["result"]
    assert actual_result == "ok", f"expected completed result 'ok', got {actual_result!r}"


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


def _register_workflow_type(ctx, domain: str, name: str, version: str = "1.0") -> dict:
    swf = ctx.client("swf")
    swf.register_workflow_type(domain=domain, name=name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": name, "version": version}))
    return {"name": name, "version": version}


def _register_activity_type(ctx, domain: str, name: str, version: str = "1.0") -> dict:
    swf = ctx.client("swf")
    swf.register_activity_type(domain=domain, name=name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": name, "version": version}))
    return {"name": name, "version": version}


def _start_workflow(
    ctx,
    domain: str,
    workflow_id: str,
    workflow_type: dict,
    task_list: str,
    exec_timeout: str = "3600",
    task_timeout: str = "60",
) -> str:
    swf = ctx.client("swf")
    resp = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType=workflow_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout=exec_timeout,
        taskStartToCloseTimeout=task_timeout,
        childPolicy="TERMINATE",
    )
    return resp["runId"]


def _safe_terminate(ctx, domain: str, workflow_id: str) -> None:
    swf = ctx.client("swf")
    try:
        swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises. An unexpected success raises, so an
    emulator accepting a call AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
