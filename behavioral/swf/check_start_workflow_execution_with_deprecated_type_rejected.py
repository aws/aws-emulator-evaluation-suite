"""start-workflow-execution-with-deprecated-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-workflow-execution-with-deprecated-type-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartWorkflowExecution against a DEPRECATED workflow type is rejected and creates no execution;
    undeprecating the identical type restores the identical call."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    version = "1.0"
    wf_name = ctx.unique_name("sim2real-swf-wf-")
    workflow_type = {"name": wf_name, "version": version}
    swf.register_workflow_type(
        domain=domain,
        name=wf_name,
        version=version,
        defaultTaskList={"name": "default"},
        defaultTaskStartToCloseTimeout="30",
        defaultExecutionStartToCloseTimeout="60",
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", workflow_type))

    # positive control: the still-active type starts successfully
    control_workflow_id = ctx.unique_name("sim2real-swf-exec-ctl-")
    control = swf.start_workflow_execution(
        domain=domain, workflowId=control_workflow_id, workflowType=workflow_type, taskList={"name": "default"}
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: swf.terminate_workflow_execution(domain=domain, workflowId=control_workflow_id))
    )
    assert control.get("runId")
    control_desc = swf.describe_workflow_execution(
        domain=domain, execution={"workflowId": control_workflow_id, "runId": control["runId"]}
    )
    assert control_desc["executionInfo"]["executionStatus"] == "OPEN"

    # break exactly one thing: deprecate the type
    swf.deprecate_workflow_type(domain=domain, workflowType=workflow_type)

    deprecated_workflow_id = ctx.unique_name("sim2real-swf-exec-dep-")
    start_call = lambda: swf.start_workflow_execution(
        domain=domain,
        workflowId=deprecated_workflow_id,
        workflowType=workflow_type,
        taskList={"name": "default"},
    )
    code, message = _error(start_call)
    assert code == "TypeDeprecatedFault", f"expected TypeDeprecatedFault, got {code!r}"
    expected = f"WorkflowType=[name={wf_name}, version={version}]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no execution (open or closed) was created for this workflowId
    open_execs = swf.list_open_workflow_executions(
        domain=domain,
        startTimeFilter={"oldestDate": 0},
        executionFilter={"workflowId": deprecated_workflow_id},
    )
    assert open_execs["executionInfos"] == []
    closed_execs = swf.list_closed_workflow_executions(
        domain=domain,
        startTimeFilter={"oldestDate": 0},
        executionFilter={"workflowId": deprecated_workflow_id},
    )
    assert closed_execs["executionInfos"] == []

    # restore: undeprecate the identical type, then the identical call now succeeds
    swf.undeprecate_workflow_type(domain=domain, workflowType=workflow_type)
    restored = start_call()
    ctx.on_cleanup(
        lambda: _safe(lambda: swf.terminate_workflow_execution(domain=domain, workflowId=deprecated_workflow_id))
    )
    assert restored.get("runId")
    restored_desc = swf.describe_workflow_execution(
        domain=domain, execution={"workflowId": deprecated_workflow_id, "runId": restored["runId"]}
    )
    assert restored_desc["executionInfo"]["executionStatus"] == "OPEN"


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DomainDeprecatedFault",
            "TypeDeprecatedFault",
            "UnknownResourceFault",
        ):
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected TypeDeprecatedFault but the call SUCCEEDED: {result!r}")


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
