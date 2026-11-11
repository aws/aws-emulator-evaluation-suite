"""get-workflow-history-unknown-execution-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-workflow-history-unknown-execution-error"
GROUP = "error-semantics"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetWorkflowExecutionHistory for a workflowId/runId pair absent from the domain raises
    UnknownResourceFault rather than returning an empty event list, while the same call
    against a real execution returns its ordered, non-empty history."""
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

    # positive control: a real execution returns a non-empty, ordered history
    history = swf.get_workflow_execution_history(
        domain=domain, execution={"workflowId": workflow_id, "runId": run_id}
    )
    assert len(history["events"]) >= 1, (
        f"positive control: expected a non-empty history for {workflow_id!r}/{run_id!r}, "
        f"got {history['events']!r}"
    )
    assert history["events"][0]["eventType"] == "WorkflowExecutionStarted", (
        f"positive control: expected the first history event to be WorkflowExecutionStarted, "
        f"got {history['events'][0]['eventType']!r}"
    )

    # the real runId paired with a workflowId that was never started -- no execution has
    # this (workflowId, runId) pair
    unknown_workflow_id = ctx.unique_name("sim2real-behav-nowfid-")
    code, message = _error(
        lambda: swf.get_workflow_execution_history(
            domain=domain, execution={"workflowId": unknown_workflow_id, "runId": run_id}
        )
    )
    assert code == "UnknownResourceFault", (
        f"GetWorkflowExecutionHistory for an unknown (workflowId, runId) pair "
        f"({unknown_workflow_id!r}, {run_id!r}) returned {code!r}, expected "
        f'"UnknownResourceFault"'
    )
    expected = (
        f"Unknown execution: WorkflowExecution=[workflowId={unknown_workflow_id}, runId={run_id}]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
