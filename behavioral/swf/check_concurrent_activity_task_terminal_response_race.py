"""concurrent-activity-task-terminal-response-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-activity-task-terminal-response-race"
GROUP = "concurrency"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once one terminal response (Completed or Failed) is accepted for an activity
    task token, a racing, differing terminal response for the SAME token is rejected
    rather than overwriting the outcome."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-cat-tl-")
    workflow_id = ctx.unique_name("sim2real-swf-cat-wf-")
    wf_name = ctx.unique_name("sim2real-swf-cat-wftype-")
    act_name = ctx.unique_name("sim2real-swf-cat-acttype-")
    version = "1.0"

    swf.register_workflow_type(
        domain=domain,
        name=wf_name,
        version=version,
        defaultTaskList={"name": task_list},
        defaultTaskStartToCloseTimeout="60",
        defaultExecutionStartToCloseTimeout="180",
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": version}))
    swf.register_activity_type(
        domain=domain,
        name=act_name,
        version=version,
        defaultTaskList={"name": task_list},
        defaultTaskHeartbeatTimeout="60",
        defaultTaskStartToCloseTimeout="60",
        defaultTaskScheduleToStartTimeout="60",
        defaultTaskScheduleToCloseTimeout="120",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", {"name": act_name, "version": version}))

    run_id = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_name, "version": version},
        taskList={"name": task_list},
    )["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}
    ctx.on_cleanup(
        lambda: _safe(
            lambda: swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id)
        )
    )

    decision_task = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
    assert decision_task.get("taskToken"), f"expected a decision task token, got {decision_task}"
    swf.respond_decision_task_completed(
        taskToken=decision_task["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_name, "version": version},
                    "activityId": "act-1",
                    "taskList": {"name": task_list},
                    "heartbeatTimeout": "60",
                    "scheduleToStartTimeout": "60",
                    "scheduleToCloseTimeout": "120",
                    "startToCloseTimeout": "60",
                },
            }
        ],
    )

    activity_task = swf.poll_for_activity_task(domain=domain, taskList={"name": task_list})
    assert activity_task.get("taskToken"), f"expected an activity task token, got {activity_task}"
    token = activity_task["taskToken"]

    def _complete():
        swf.respond_activity_task_completed(taskToken=token, result="ok")
        return "completed"

    def _fail():
        swf.respond_activity_task_failed(taskToken=token, reason="boom")
        return "failed"

    outcomes = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_complete = pool.submit(_complete)
        fut_fail = pool.submit(_fail)
        for name, fut in (("completed", fut_complete), ("failed", fut_fail)):
            try:
                outcomes[name] = ("ok", fut.result())
            except Exception as err:  # noqa: BLE001
                code = getattr(err, "response", {}).get("Error", {}).get("Code")
                outcomes[name] = ("error", code, getattr(err, "response", {}).get("Error", {}).get("Message"))

    successes = [k for k, v in outcomes.items() if v[0] == "ok"]
    failures = [k for k, v in outcomes.items() if v[0] == "error"]
    assert len(successes) == 1, f"expected exactly one terminal response to win, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one terminal response to be rejected, got {outcomes}"
    rejected_code = outcomes[failures[0]][1]
    assert rejected_code == "UnknownResourceFault", f"expected UnknownResourceFault, got {rejected_code}"

    history = swf.get_workflow_execution_history(domain=domain, execution=execution)["events"]
    # Either losing response is refused with the same message naming the closed activity.
    scheduled_id = next(e["eventId"] for e in history if e["eventType"] == "ActivityTaskScheduled")
    rejected_message = outcomes[failures[0]][2]
    assert rejected_message == f"Unknown activity, scheduledEventId = {scheduled_id}", rejected_message
    completed_events = [e for e in history if e["eventType"] == "ActivityTaskCompleted"]
    failed_events = [e for e in history if e["eventType"] == "ActivityTaskFailed"]
    winner = successes[0]
    if winner == "completed":
        assert len(completed_events) == 1, "winning ActivityTaskCompleted event missing/duplicated"
        assert len(failed_events) == 0, "losing response's effect (ActivityTaskFailed) leaked into history"
    else:
        assert len(failed_events) == 1, "winning ActivityTaskFailed event missing/duplicated"
        assert len(completed_events) == 0, "losing response's effect (ActivityTaskCompleted) leaked into history"


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
