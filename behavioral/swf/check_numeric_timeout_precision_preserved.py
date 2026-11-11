"""numeric-timeout-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "numeric-timeout-precision-preserved"
GROUP = "representation"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """String-encoded numeric timeouts round-trip exactly, without rounding or truncation."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    wf_type = _register_workflow_type(ctx, domain, ctx.unique_name("sim2real-swf-wft-"))
    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    task_list = ctx.unique_name("sim2real-swf-tl-")

    # Deliberately odd, non-round values that a numeric round-trip through float/rounding
    # logic would be likely to mangle.
    exec_timeout = "86399"
    task_timeout = "47"

    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, task_list, exec_timeout, task_timeout)
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, workflow_id))
    execution = {"workflowId": workflow_id, "runId": run_id}

    described = swf.describe_workflow_execution(domain=domain, execution=execution)
    config = described["executionConfiguration"]
    assert config["executionStartToCloseTimeout"] == exec_timeout, (
        f"executionStartToCloseTimeout mangled: {config['executionStartToCloseTimeout']!r} != {exec_timeout!r}"
    )
    assert config["taskStartToCloseTimeout"] == task_timeout, (
        f"taskStartToCloseTimeout mangled: {config['taskStartToCloseTimeout']!r} != {task_timeout!r}"
    )

    # And the value recorded in the WorkflowExecutionStarted history event must match too.
    history = swf.get_workflow_execution_history(domain=domain, execution=execution)
    started = [e for e in history["events"] if e["eventType"] == "WorkflowExecutionStarted"][0]
    attrs = started["workflowExecutionStartedEventAttributes"]
    assert attrs["executionStartToCloseTimeout"] == exec_timeout, (
        f"history executionStartToCloseTimeout mangled: "
        f"{attrs['executionStartToCloseTimeout']!r} != {exec_timeout!r}"
    )
    assert attrs["taskStartToCloseTimeout"] == task_timeout, (
        f"history taskStartToCloseTimeout mangled: {attrs['taskStartToCloseTimeout']!r} != {task_timeout!r}"
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
    exec_timeout: str,
    task_timeout: str,
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
