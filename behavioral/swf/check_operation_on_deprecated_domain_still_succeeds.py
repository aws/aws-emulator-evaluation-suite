"""operation-on-deprecated-domain-still-succeeds."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "operation-on-deprecated-domain-still-succeeds"
GROUP = "overly-permissive"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeprecateDomain, the domain reads DEPRECATED while its existing workflow type stays REGISTERED, a new
    type registers into it and StartWorkflowExecution still opens an execution: SWF does not refuse these calls."""
    swf = ctx.client("swf")
    domain = ctx.unique_name("sim2real-behav-domain-")
    swf.register_domain(
        name=domain,
        workflowExecutionRetentionPeriodInDays="1",
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort_deprecate(swf, domain))

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
    workflow_type = {"name": wt_name, "version": "1.0"}

    # Positive control: starting a workflow execution succeeds while the domain is still active.
    control_wf_id = ctx.unique_name("sim2real-behav-wf-ctl-")
    swf.start_workflow_execution(domain=domain, workflowId=control_wf_id, workflowType=workflow_type)
    ctx.on_cleanup(lambda: _best_effort_terminate(swf, domain, control_wf_id))
    control_info = swf.describe_workflow_execution(
        domain=domain, execution={"workflowId": control_wf_id, "runId": _run_id(swf, domain, control_wf_id)}
    )
    assert control_info["executionInfo"]["executionStatus"] == "OPEN", (
        f"expected control execution {control_wf_id!r} OPEN before deprecation, "
        f"got {control_info['executionInfo']['executionStatus']!r}"
    )

    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
    swf.deprecate_domain(name=domain)
    # DeprecateDomain's status change can lag briefly; wait for it to actually land before probing.
    _wait_for_domain_status(swf, domain, "DEPRECATED")

    # The pre-existing workflow type is NOT cascade-deprecated by the domain's deprecation.
    type_info = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)
    assert type_info["typeInfo"]["status"] == "REGISTERED", (
        f"expected pre-existing workflow type {workflow_type!r} to stay REGISTERED after "
        f"the domain was deprecated, got {type_info['typeInfo']['status']!r}"
    )

    # A NEW workflow type can still be registered into the deprecated domain.
    new_wt_name = ctx.unique_name("sim2real-behav-wt-post-deprecate-")
    swf.register_workflow_type(
        domain=domain,
        name=new_wt_name,
        version="1.0",
        defaultTaskStartToCloseTimeout="30",
        defaultExecutionStartToCloseTimeout="60",
        defaultTaskList={"name": tasklist},
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(
        lambda: _best_effort_deprecate_type(swf, domain, {"name": new_wt_name, "version": "1.0"})
    )
    new_type_info = swf.describe_workflow_type(domain=domain, workflowType={"name": new_wt_name, "version": "1.0"})
    assert new_type_info["typeInfo"]["status"] == "REGISTERED", (
        f"expected {new_wt_name!r} registered into the now-deprecated domain to land REGISTERED, "
        f"got {new_type_info['typeInfo']['status']!r}"
    )

    # StartWorkflowExecution for the pre-existing type still succeeds too.
    post_wf_id = ctx.unique_name("sim2real-behav-wf-post-deprecate-")
    swf.start_workflow_execution(domain=domain, workflowId=post_wf_id, workflowType=workflow_type)
    ctx.on_cleanup(lambda: _best_effort_terminate(swf, domain, post_wf_id))
    post_info = swf.describe_workflow_execution(
        domain=domain, execution={"workflowId": post_wf_id, "runId": _run_id(swf, domain, post_wf_id)}
    )
    assert post_info["executionInfo"]["executionStatus"] == "OPEN", (
        f"expected execution {post_wf_id!r} started against the deprecated domain to be OPEN, "
        f"got {post_info['executionInfo']['executionStatus']!r}"
    )

    # Read-only DescribeDomain keeps working against the deprecated domain.
    domain_info = swf.describe_domain(name=domain)
    assert domain_info["domainInfo"]["status"] == "DEPRECATED", (
        f"expected DescribeDomain to keep reporting {domain!r} DEPRECATED, "
        f"got {domain_info['domainInfo']['status']!r}"
    )


def _run_id(swf, domain, workflow_id):
    execs = swf.list_open_workflow_executions(
        domain=domain,
        startTimeFilter={"oldestDate": 0},
        executionFilter={"workflowId": workflow_id},
    )
    return execs["executionInfos"][0]["execution"]["runId"]


def _best_effort_deprecate(swf, name):
    try:
        swf.deprecate_domain(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DomainDeprecatedFault", "UnknownResourceFault"):
            raise


def _best_effort_deprecate_type(swf, domain, workflow_type):
    try:
        swf.deprecate_workflow_type(domain=domain, workflowType=workflow_type)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("TypeDeprecatedFault", "UnknownResourceFault"):
            raise


def _best_effort_terminate(swf, domain, workflow_id):
    try:
        swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


def _wait_for_domain_status(swf, name, want, timeout=60, interval=2):
    import time

    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = swf.describe_domain(name=name)["domainInfo"]["status"]
        if last == want:
            return
        time.sleep(interval)
    raise AssertionError(f"domain {name} status {last!r} never reached {want!r} within {timeout}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


