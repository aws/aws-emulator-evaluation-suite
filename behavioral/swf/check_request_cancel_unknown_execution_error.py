"""request-cancel-unknown-execution-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-cancel-unknown-execution-error"
GROUP = "error-semantics"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestCancelWorkflowExecution for a workflowId that never existed in the domain raises
    UnknownResourceFault; against a real OPEN execution it succeeds and records a
    WorkflowExecutionCancelRequested history event."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    wf_name = ctx.unique_name("sim2real-behav-wftype-")
    version = "1.0"
    swf.register_workflow_type(domain=domain, name=wf_name, version=version)
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": version}))

    workflow_id = ctx.unique_name("sim2real-behav-wfid-")
    started = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_name, "version": version},
        taskList={"name": ctx.unique_name("sim2real-behav-tl-")},
        executionStartToCloseTimeout="120",
        taskStartToCloseTimeout="60",
        childPolicy="TERMINATE",
    )
    run_id = started["runId"]
    ctx.on_cleanup(lambda: _terminate_quiet(swf, domain, workflow_id))

    # positive control: a real OPEN execution accepts the cancel request
    swf.request_cancel_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id)
    history = swf.get_workflow_execution_history(
        domain=domain, execution={"workflowId": workflow_id, "runId": run_id}
    )
    event_types = [e["eventType"] for e in history["events"]]
    assert "WorkflowExecutionCancelRequested" in event_types, (
        f"expected WorkflowExecutionCancelRequested in history, got {event_types}"
    )

    # a workflowId that was never started in this domain
    unknown_workflow_id = ctx.unique_name("sim2real-behav-nowfid-")
    code, message = _error(
        lambda: swf.request_cancel_workflow_execution(domain=domain, workflowId=unknown_workflow_id)
    )
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault for unknown workflowId, got {code}"
    expected = f"Unknown execution, workflowId = {unknown_workflow_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent, via an independent read: no execution was ever created for this workflowId
    describe_code, describe_message = _error(
        lambda: swf.describe_workflow_execution(
            domain=domain, execution={"workflowId": unknown_workflow_id, "runId": "bogus-run-id"}
        )
    )
    assert describe_code == "UnknownResourceFault", (
        f"expected UnknownResourceFault describing unknown workflowId, got {describe_code}"
    )
    expected = (
        f"Unknown execution: WorkflowExecution=[workflowId={unknown_workflow_id}, runId=bogus-run-id]"
    )
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"


def _terminate_quiet(swf, domain, workflow_id):
    try:
        swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


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
