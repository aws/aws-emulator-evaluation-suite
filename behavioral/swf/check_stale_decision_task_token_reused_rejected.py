"""stale-decision-task-token-reused-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stale-decision-task-token-reused-rejected"
GROUP = "ordering"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a decision taskToken already consumed by RespondDecisionTaskCompleted is rejected."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    wf_type = _register_workflow_type(ctx, domain, ctx.unique_name("sim2real-swf-wft-"))
    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    task_list = ctx.unique_name("sim2real-swf-tl-")

    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, task_list)
    execution = {"workflowId": workflow_id, "runId": run_id}

    decision = swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})
    assert decision.get("taskToken"), f"expected a decision task token, got {decision!r}"
    token = decision["taskToken"]

    # Positive control: the fresh token completes the decision task and closes the workflow.
    swf.respond_decision_task_completed(
        taskToken=token,
        decisions=[
            {
                "decisionType": "CompleteWorkflowExecution",
                "completeWorkflowExecutionDecisionAttributes": {"result": "done"},
            }
        ],
    )
    described = swf.describe_workflow_execution(domain=domain, execution=execution)
    assert described["executionInfo"]["executionStatus"] == "CLOSED", (
        f"expected CLOSED after the fresh-token completion, got {described['executionInfo']['executionStatus']!r}"
    )
    assert described["executionInfo"]["closeStatus"] == "COMPLETED", (
        f"expected COMPLETED after the fresh-token completion, got {described['executionInfo'].get('closeStatus')!r}"
    )
    history_before = swf.get_workflow_execution_history(domain=domain, execution=execution)
    events_before = [e["eventType"] for e in history_before["events"]]

    # Break exactly one thing: reuse the same, now-consumed token.
    code, message = _error(
        lambda: swf.respond_decision_task_completed(
            taskToken=token,
            decisions=[
                {
                    "decisionType": "CompleteWorkflowExecution",
                    "completeWorkflowExecutionDecisionAttributes": {"result": "done-again"},
                }
            ],
        )
    )
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault, got {code!r}"
    expected = f"Unknown execution: WorkflowExecution=[workflowId={workflow_id}, runId={run_id}]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no new history events were recorded, and the workflow is still
    # closed with the original COMPLETED status (not overwritten by the replay).
    history_after = swf.get_workflow_execution_history(domain=domain, execution=execution)
    events_after = [e["eventType"] for e in history_after["events"]]
    assert events_after == events_before, "stale token reuse produced extra history events"
    described_after = swf.describe_workflow_execution(domain=domain, execution=execution)
    assert described_after["executionInfo"]["executionStatus"] == "CLOSED", (
        f"stale token reuse changed executionStatus to {described_after['executionInfo']['executionStatus']!r}"
    )
    assert described_after["executionInfo"]["closeStatus"] == "COMPLETED", (
        f"stale token reuse overwrote closeStatus with {described_after['executionInfo'].get('closeStatus')!r}"
    )


def _register_workflow_type(ctx, domain: str, name: str, version: str = "1.0") -> dict:
    swf = ctx.client("swf")
    swf.register_workflow_type(domain=domain, name=name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": name, "version": version}))
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


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
