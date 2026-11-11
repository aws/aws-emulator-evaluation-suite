"""empty-vs-absent-input-preserved."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "empty-vs-absent-input-preserved"
GROUP = "representation"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicitly empty-string workflow input and an absent input field round-trip through
    history distinctly: one preserves an empty string, the other omits the field entirely --
    neither is coerced into the other."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)

    empty_id = ctx.unique_name("sim2real-exec-empty-")
    empty_resp = swf.start_workflow_execution(
        domain=domain,
        workflowId=empty_id,
        workflowType=wf_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout="300",
        taskStartToCloseTimeout="30",
        childPolicy="TERMINATE",
        input="",
    )
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, empty_id))

    absent_id = ctx.unique_name("sim2real-exec-absent-")
    absent_resp = swf.start_workflow_execution(
        domain=domain,
        workflowId=absent_id,
        workflowType=wf_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout="300",
        taskStartToCloseTimeout="30",
        childPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, absent_id))

    empty_attrs = _started_attrs(swf, domain, empty_id, empty_resp["runId"])
    absent_attrs = _started_attrs(swf, domain, absent_id, absent_resp["runId"])

    assert "input" in empty_attrs, "explicit empty-string input was dropped from history"
    assert empty_attrs["input"] == "", f"expected empty string input, got {empty_attrs['input']!r}"
    assert "input" not in absent_attrs, (
        f"absent input was coerced into a present field: {absent_attrs.get('input')!r}"
    )


def _started_attrs(swf, domain: str, workflow_id: str, run_id: str) -> dict:
    history = swf.get_workflow_execution_history(
        domain=domain, execution={"workflowId": workflow_id, "runId": run_id}, maximumPageSize=100
    )["events"]
    started = [e for e in history if e["eventType"] == "WorkflowExecutionStarted"]
    assert len(started) == 1, f"expected exactly one WorkflowExecutionStarted event, got {len(started)}"
    return started[0]["workflowExecutionStartedEventAttributes"]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
