"""history-reverse-order-matches-forward."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "history-reverse-order-matches-forward"
GROUP = "data-plane"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetWorkflowExecutionHistory with reverseOrder=true returns the exact same event set as
    forward order, strictly reversed, with byte-identical event payloads."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)
    workflow_id = ctx.unique_name("sim2real-exec-")
    resp = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType=wf_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout="300",
        taskStartToCloseTimeout="30",
        childPolicy="TERMINATE",
        input="reverse-order-check",
    )
    run_id = resp["runId"]
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, workflow_id))
    execution = {"workflowId": workflow_id, "runId": run_id}

    swf.signal_workflow_execution(
        domain=domain, workflowId=workflow_id, runId=run_id, signalName="ping", input="pong"
    )

    forward = swf.get_workflow_execution_history(
        domain=domain, execution=execution, maximumPageSize=1000, reverseOrder=False
    )["events"]
    reverse = swf.get_workflow_execution_history(
        domain=domain, execution=execution, maximumPageSize=1000, reverseOrder=True
    )["events"]

    # WorkflowExecutionStarted + DecisionTaskScheduled + one WorkflowExecutionSignaled.
    assert len(forward) >= 3, f"expected at least 3 events (start+decision+signal), got {len(forward)}"
    assert len(forward) == len(reverse), (
        f"forward and reverse returned different event counts: forward={len(forward)} reverse={len(reverse)}"
    )
    assert reverse == list(reversed(forward)), "reverseOrder result is not the exact reverse of forward order"
    forward_ids = [e["eventId"] for e in forward]
    reverse_ids = [e["eventId"] for e in reverse]
    assert reverse_ids == list(reversed(forward_ids)), (
        f"reverseOrder eventIds are not the exact reverse: forward={forward_ids} reverse={reverse_ids}"
    )


def _register_workflow_type(ctx, domain: str, task_list: str) -> dict:
    swf = ctx.client("swf")
    name = ctx.unique_name("sim2real-wf-")
    version = "1.0"
    swf.register_workflow_type(
        domain=domain,
        name=name,
        version=version,
        defaultTaskStartToCloseTimeout="30",
        defaultExecutionStartToCloseTimeout="300",
        defaultTaskList={"name": task_list},
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": name, "version": version}))
    return {"name": name, "version": version}


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
