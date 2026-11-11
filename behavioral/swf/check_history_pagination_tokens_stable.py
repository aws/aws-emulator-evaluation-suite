"""history-pagination-tokens-stable."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "history-pagination-tokens-stable"
GROUP = "data-plane"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetWorkflowExecutionHistory nextPageToken cursors yield the full, non-overlapping,
    ascending-eventId event stream identical to a single unpaginated fetch."""
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
        input="seed",
    )
    run_id = resp["runId"]
    ctx.on_cleanup(lambda: _safe_terminate(ctx, domain, workflow_id))
    execution = {"workflowId": workflow_id, "runId": run_id}

    for i in range(5):
        swf.signal_workflow_execution(
            domain=domain,
            workflowId=workflow_id,
            runId=run_id,
            signalName=f"sig-{i}",
            input=f"payload-{i}",
        )

    full = swf.get_workflow_execution_history(
        domain=domain, execution=execution, maximumPageSize=1000, reverseOrder=False
    )["events"]
    # WorkflowExecutionStarted + DecisionTaskScheduled + one WorkflowExecutionSignaled per signal.
    assert len(full) >= 7, f"expected at least 7 events (start+decision+5 signals), got {len(full)} events"

    paginated: list[dict] = []
    token = None
    pages = 0
    while True:
        kwargs = dict(domain=domain, execution=execution, maximumPageSize=2, reverseOrder=False)
        if token:
            kwargs["nextPageToken"] = token
        page = swf.get_workflow_execution_history(**kwargs)
        paginated.extend(page["events"])
        pages += 1
        token = page.get("nextPageToken")
        if not token or pages > 100:
            break

    assert pages > 1, "expected pagination to actually occur with maximumPageSize=2"
    assert len(paginated) == len(full), f"paginated={len(paginated)} full={len(full)}"

    event_ids = [e["eventId"] for e in paginated]
    assert event_ids == sorted(event_ids), "eventIds are not ascending across pages"
    assert len(set(event_ids)) == len(event_ids), "duplicate eventId across pages"
    assert event_ids == [e["eventId"] for e in full], (
        f"paginated eventIds {event_ids} do not match unpaginated eventIds "
        f"{[e['eventId'] for e in full]}"
    )
    assert paginated == full, "paginated event stream does not match unpaginated fetch"


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
