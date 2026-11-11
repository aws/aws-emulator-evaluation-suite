"""activity-result-binary-blob-round-trip."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "activity-result-binary-blob-round-trip"
GROUP = "representation"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A base64-encoded binary activity result is preserved byte-identical in history."""
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
    assert decision.get("taskToken"), f"expected a decision task token, got {decision!r}"
    swf.respond_decision_task_completed(
        taskToken=decision["taskToken"],
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
    assert activity.get("taskToken"), f"expected an activity task token, got {activity!r}"

    binary_blob = os.urandom(96)
    b64_result = base64.b64encode(binary_blob).decode("ascii")
    swf.respond_activity_task_completed(taskToken=activity["taskToken"], result=b64_result)

    history = swf.get_workflow_execution_history(domain=domain, execution=execution)
    completed = [e for e in history["events"] if e["eventType"] == "ActivityTaskCompleted"]
    assert len(completed) == 1, f"expected exactly one ActivityTaskCompleted event, got {len(completed)}"
    attrs = completed[0]["activityTaskCompletedEventAttributes"]
    assert attrs["result"] == b64_result, "base64 activity result was not preserved byte-identical"
    assert base64.b64decode(attrs["result"]) == binary_blob, "decoded history result did not match the original binary blob"


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
