"""child-policy-terminate-enforced-on-parent-termination."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "child-policy-terminate-enforced-on-parent-termination"
GROUP = "server-side"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Terminating a parent execution applies the child's TERMINATE child policy to its open child execution:
    the child closes TERMINATED with cause CHILD_POLICY_APPLIED, with no call made against the child."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    wf_type = _register_workflow_type(ctx, domain, ctx.unique_name("sim2real-swf-wft-"))
    parent_task_list = ctx.unique_name("sim2real-swf-ptl-")
    child_task_list = ctx.unique_name("sim2real-swf-ctl-")
    parent_id = ctx.unique_name("sim2real-swf-parent-")
    child_id = ctx.unique_name("sim2real-swf-child-")

    parent_run_id = swf.start_workflow_execution(
        domain=domain,
        workflowId=parent_id,
        workflowType=wf_type,
        taskList={"name": parent_task_list},
        executionStartToCloseTimeout="300",
        taskStartToCloseTimeout="60",
        childPolicy="TERMINATE",
    )["runId"]
    parent_execution = {"workflowId": parent_id, "runId": parent_run_id}
    ctx.on_cleanup(
        lambda: _safe(lambda: swf.terminate_workflow_execution(domain=domain, workflowId=parent_id, runId=parent_run_id))
    )

    # Drive the parent's decider to schedule a child workflow, with an explicit TERMINATE
    # child policy on the child.
    decision = swf.poll_for_decision_task(domain=domain, taskList={"name": parent_task_list})
    assert decision.get("taskToken"), "no decision task was scheduled for the parent"
    swf.respond_decision_task_completed(
        taskToken=decision["taskToken"],
        decisions=[
            {
                "decisionType": "StartChildWorkflowExecution",
                "startChildWorkflowExecutionDecisionAttributes": {
                    "workflowType": wf_type,
                    "workflowId": child_id,
                    "taskList": {"name": child_task_list},
                    "executionStartToCloseTimeout": "300",
                    "taskStartToCloseTimeout": "60",
                    "childPolicy": "TERMINATE",
                },
            }
        ],
    )

    started_evt = _poll_until(
        lambda: _find_event(swf, domain, parent_execution, "ChildWorkflowExecutionStarted"),
        lambda evt: evt is not None,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert started_evt is not None, "child workflow execution never reported as started to the parent"
    child_run_id = started_evt["childWorkflowExecutionStartedEventAttributes"]["workflowExecution"]["runId"]
    child_execution = {"workflowId": child_id, "runId": child_run_id}
    ctx.on_cleanup(
        lambda: _safe(lambda: swf.terminate_workflow_execution(domain=domain, workflowId=child_id, runId=child_run_id))
    )
    child_status = swf.describe_workflow_execution(domain=domain, execution=child_execution)
    assert child_status["executionInfo"]["executionStatus"] == "OPEN", "child must be open before we terminate the parent"

    # The single client action: terminate the parent. No call is ever made against the child.
    swf.terminate_workflow_execution(domain=domain, workflowId=parent_id, runId=parent_run_id)

    child_closed = _poll_until(
        lambda: swf.describe_workflow_execution(domain=domain, execution=child_execution)["executionInfo"],
        lambda info: info["executionStatus"] == "CLOSED",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert child_closed["executionStatus"] == "CLOSED", "child execution was never closed after parent termination"
    assert child_closed["closeStatus"] == "TERMINATED", f"expected TERMINATED, got {child_closed['closeStatus']}"

    terminated_evt = _find_event(swf, domain, child_execution, "WorkflowExecutionTerminated")
    assert terminated_evt is not None, "no WorkflowExecutionTerminated event recorded on the child's history"
    attrs = terminated_evt["workflowExecutionTerminatedEventAttributes"]
    assert attrs["childPolicy"] == "TERMINATE", f"expected childPolicy TERMINATE, got {attrs['childPolicy']!r}"
    assert attrs.get("cause") == "CHILD_POLICY_APPLIED", f"expected CHILD_POLICY_APPLIED, got {attrs.get('cause')!r}"

    parent_status = swf.describe_workflow_execution(domain=domain, execution=parent_execution)
    actual_parent_status = parent_status["executionInfo"]["executionStatus"]
    assert actual_parent_status == "CLOSED", f"expected parent executionStatus CLOSED, got {actual_parent_status!r}"
    actual_parent_close = parent_status["executionInfo"]["closeStatus"]
    assert actual_parent_close == "TERMINATED", f"expected parent closeStatus TERMINATED, got {actual_parent_close!r}"


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


def _register_workflow_type(ctx, domain: str, name: str, version: str = "1.0") -> dict:
    swf = ctx.client("swf")
    swf.register_workflow_type(domain=domain, name=name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": name, "version": version}))
    return {"name": name, "version": version}


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
