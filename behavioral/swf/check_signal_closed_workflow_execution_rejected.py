"""signal-closed-workflow-execution-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signal-closed-workflow-execution-rejected"
GROUP = "overly-permissive"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SignalWorkflowExecution against an execution that has already been terminated is
    rejected with UnknownResourceFault -- the signal is not silently accepted or queued for
    a run that no longer exists."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    wf_type = _register_workflow_type(ctx, domain, ctx.unique_name("sim2real-swf-wft-"))
    task_list = ctx.unique_name("sim2real-swf-tl-")

    # Positive control: an OPEN execution accepts a signal.
    open_workflow_id = ctx.unique_name("sim2real-swf-open-")
    open_run_id = _start_workflow(ctx, domain, open_workflow_id, wf_type, task_list)
    open_execution = {"workflowId": open_workflow_id, "runId": open_run_id}
    ctx.on_cleanup(
        lambda: _safe(lambda: swf.terminate_workflow_execution(domain=domain, workflowId=open_workflow_id, runId=open_run_id))
    )

    swf.signal_workflow_execution(
        domain=domain, workflowId=open_workflow_id, runId=open_run_id, signalName="go", input="payload"
    )
    signaled = _find_event(swf, domain, open_execution, "WorkflowExecutionSignaled")
    assert signaled is not None, "signal to an open execution did not record a history event"
    assert signaled["workflowExecutionSignaledEventAttributes"]["signalName"] == "go", (
        f"expected signalName 'go', got {signaled['workflowExecutionSignaledEventAttributes']['signalName']!r}"
    )
    assert signaled["workflowExecutionSignaledEventAttributes"]["input"] == "payload", (
        f"expected input 'payload', got {signaled['workflowExecutionSignaledEventAttributes']['input']!r}"
    )

    # Break exactly one thing: signal a workflowId/runId that has already been terminated.
    closed_workflow_id = ctx.unique_name("sim2real-swf-closed-")
    closed_run_id = _start_workflow(ctx, domain, closed_workflow_id, wf_type, task_list)
    closed_execution = {"workflowId": closed_workflow_id, "runId": closed_run_id}
    swf.terminate_workflow_execution(domain=domain, workflowId=closed_workflow_id, runId=closed_run_id)
    described = swf.describe_workflow_execution(domain=domain, execution=closed_execution)
    assert described["executionInfo"]["executionStatus"] == "CLOSED", (
        f"expected executionStatus CLOSED after termination, got {described['executionInfo']['executionStatus']!r}"
    )

    code, message = _error(
        lambda: swf.signal_workflow_execution(
            domain=domain, workflowId=closed_workflow_id, runId=closed_run_id, signalName="go", input="payload"
        )
    )
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault, got {code!r}"
    expected = f"Unknown execution: WorkflowExecution=[workflowId={closed_workflow_id}, runId={closed_run_id}]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the closed execution's history has no signal event.
    missing = _find_event(swf, domain, closed_execution, "WorkflowExecutionSignaled")
    assert missing is None, "a signal was recorded against an already-terminated execution"


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


def _find_event(swf, domain, execution, event_type):
    events = swf.get_workflow_execution_history(domain=domain, execution=execution)["events"]
    for evt in events:
        if evt["eventType"] == event_type:
            return evt
    return None


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
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
