"""request-cancel-unknown-execution-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-cancel-unknown-execution-rejected"
GROUP = "error-semantics"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestCancelWorkflowExecution on a workflowId that never existed returns UnknownResourceFault, not a silent
    success, while the same call against a genuinely open execution records the cancel request."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    tasklist = ctx.unique_name("sim2real-behav-tl-")
    wt_name = ctx.unique_name("sim2real-behav-wt-")
    swf.register_workflow_type(
        domain=domain,
        name=wt_name,
        version="1.0",
        defaultTaskStartToCloseTimeout="30",
        defaultExecutionStartToCloseTimeout="60",
        defaultTaskList={"name": tasklist},
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wt_name, "version": "1.0"}))

    # Positive control: a genuinely open execution accepts the cancel request.
    wf_id = ctx.unique_name("sim2real-behav-wf-")
    run_id = swf.start_workflow_execution(
        domain=domain, workflowId=wf_id, workflowType={"name": wt_name, "version": "1.0"}
    )["runId"]
    ctx.on_cleanup(lambda: _best_effort_terminate(swf, domain, wf_id))

    swf.request_cancel_workflow_execution(domain=domain, workflowId=wf_id, runId=run_id)
    info = swf.describe_workflow_execution(domain=domain, execution={"workflowId": wf_id, "runId": run_id})
    cancel_requested = info["executionInfo"]["cancelRequested"]
    assert cancel_requested is True, (
        f"expected cancelRequested True for real open execution {wf_id}/{run_id}, got {cancel_requested!r}"
    )

    # An execution that never existed must fail with UnknownResourceFault, not succeed silently.
    ghost_wf_id = ctx.unique_name("sim2real-behav-ghost-")
    code, message = _error(
        lambda: swf.request_cancel_workflow_execution(domain=domain, workflowId=ghost_wf_id)
    )
    assert code == "UnknownResourceFault", (
        f"expected UnknownResourceFault cancelling never-started workflowId {ghost_wf_id!r}, got {code!r}"
    )
    expected = f"Unknown execution, workflowId = {ghost_wf_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no execution was ever created for the ghost workflowId either.
    describe_code, describe_message = _error(
        lambda: swf.describe_workflow_execution(
            domain=domain, execution={"workflowId": ghost_wf_id, "runId": "bogus-run-id"}
        )
    )
    assert describe_code == "UnknownResourceFault", (
        f"expected UnknownResourceFault describing never-started workflowId {ghost_wf_id!r}, got {describe_code!r}"
    )
    expected = f"Unknown execution: WorkflowExecution=[workflowId={ghost_wf_id}, runId=bogus-run-id]"
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _best_effort_terminate(swf, domain, workflow_id):
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
