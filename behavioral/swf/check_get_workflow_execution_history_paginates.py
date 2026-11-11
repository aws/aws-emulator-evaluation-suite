"""get-workflow-execution-history-paginates."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-workflow-execution-history-paginates"
GROUP = "data-plane"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetWorkflowExecutionHistory paginates with contiguous, non-overlapping event pages."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    wf_type = _register_workflow_type(ctx, domain, ctx.unique_name("sim2real-swf-wft-"))
    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    task_list = ctx.unique_name("sim2real-swf-tl-")

    run_id = _start_workflow(ctx, domain, workflow_id, wf_type, task_list)
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, workflow_id))
    execution = {"workflowId": workflow_id, "runId": run_id}

    # Add two more history events beyond the WorkflowExecutionStarted + DecisionTaskScheduled
    # pair that StartWorkflowExecution already produces, so there are >= 4 events to paginate.
    swf.signal_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id, signalName="s1")
    swf.signal_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id, signalName="s2")

    # Full, unpaginated view used as ground truth for contiguity checks.
    full = swf.get_workflow_execution_history(domain=domain, execution=execution)
    full_ids = [e["eventId"] for e in full["events"]]
    assert len(full_ids) >= 4, f"expected >=4 history events, got {full_ids}"

    # Now walk the same history two events at a time and verify the pages are contiguous,
    # non-overlapping, and reassemble exactly into the full list.
    page_size = 2
    collected: list[int] = []
    token = None
    pages_seen = 0
    while True:
        kwargs = {"domain": domain, "execution": execution, "maximumPageSize": page_size}
        if token:
            kwargs["nextPageToken"] = token
        page = swf.get_workflow_execution_history(**kwargs)
        page_ids = [e["eventId"] for e in page["events"]]
        assert page_ids, "page unexpectedly empty"
        assert len(page_ids) <= page_size, f"page exceeded maximumPageSize={page_size}: got {len(page_ids)} events"
        collected.extend(page_ids)
        pages_seen += 1
        token = page.get("nextPageToken")
        if not token:
            break
        assert pages_seen < 20, "pagination did not terminate"

    assert pages_seen >= 2, "expected the history to require more than one page"
    assert collected == full_ids, "paginated events did not reassemble into the full history in order"
    assert len(collected) == len(set(collected)), "pagination produced overlapping/duplicate events"


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
    input_: str | None = None,
    tag_list: list[str] | None = None,
    exec_timeout: str = "3600",
    task_timeout: str = "60",
) -> str:
    swf = ctx.client("swf")
    kwargs = dict(
        domain=domain,
        workflowId=workflow_id,
        workflowType=workflow_type,
        taskList={"name": task_list},
        executionStartToCloseTimeout=exec_timeout,
        taskStartToCloseTimeout=task_timeout,
        childPolicy="TERMINATE",
    )
    if input_ is not None:
        kwargs["input"] = input_
    if tag_list is not None:
        kwargs["tagList"] = tag_list
    resp = swf.start_workflow_execution(**kwargs)
    return resp["runId"]


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
