"""activity-task-heartbeat-timeout-reaping."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "activity-task-heartbeat-timeout-reaping"
GROUP = "visibility-timeout-ttl"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An activity task whose heartbeat timeout elapses without a heartbeat is
    server-side timed out (ActivityTaskTimedOut/HEARTBEAT) and a fresh decision
    task is scheduled for the decider, with no client-side reaping logic."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-hb-tl-")
    workflow_id = ctx.unique_name("sim2real-swf-hb-wf-")
    wf_name = ctx.unique_name("sim2real-swf-hb-wftype-")
    act_name = ctx.unique_name("sim2real-swf-hb-acttype-")
    version = "1.0"

    swf.register_workflow_type(
        domain=domain,
        name=wf_name,
        version=version,
        defaultTaskList={"name": task_list},
        defaultTaskStartToCloseTimeout="60",
        defaultExecutionStartToCloseTimeout="300",
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": version}))
    swf.register_activity_type(
        domain=domain,
        name=act_name,
        version=version,
        defaultTaskList={"name": task_list},
        defaultTaskHeartbeatTimeout="8",
        defaultTaskStartToCloseTimeout="120",
        defaultTaskScheduleToStartTimeout="60",
        defaultTaskScheduleToCloseTimeout="240",
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
    assert decision_task.get("taskToken"), f"no initial decision task delivered on {task_list!r}"
    swf.respond_decision_task_completed(
        taskToken=decision_task["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_name, "version": version},
                    "activityId": "act-1",
                    "taskList": {"name": task_list},
                    "heartbeatTimeout": "8",
                    "scheduleToStartTimeout": "60",
                    "scheduleToCloseTimeout": "240",
                    "startToCloseTimeout": "120",
                },
            }
        ],
    )

    activity_task = swf.poll_for_activity_task(domain=domain, taskList={"name": task_list})
    assert activity_task.get("taskToken"), f"no activity task delivered on {task_list!r}"
    # Deliberately never call RecordActivityTaskHeartbeat -- the worker "goes dark".

    timed_out = _poll_until(
        lambda: _find_event(swf, domain, execution, "ActivityTaskTimedOut"),
        lambda evt: evt is not None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert timed_out is not None, "ActivityTaskTimedOut event never appeared"
    attrs = timed_out["activityTaskTimedOutEventAttributes"]
    assert attrs["timeoutType"] == "HEARTBEAT", f"expected HEARTBEAT timeout, got {attrs['timeoutType']}"

    # A fresh decision task must have been (re)scheduled as a consequence.
    new_decision = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
    assert new_decision.get("taskToken"), "no decision task was scheduled after the activity timeout"
    swf.respond_decision_task_completed(
        taskToken=new_decision["taskToken"],
        decisions=[
            {
                "decisionType": "CompleteWorkflowExecution",
                "completeWorkflowExecutionDecisionAttributes": {"result": "done"},
            }
        ],
    )


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


def _find_event(swf, domain, execution, event_type):
    events = swf.get_workflow_execution_history(domain=domain, execution=execution)["events"]
    for evt in events:
        if evt["eventType"] == event_type:
            return evt
    return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


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
