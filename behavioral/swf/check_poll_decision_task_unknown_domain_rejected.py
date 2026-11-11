"""poll-decision-task-unknown-domain-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "poll-decision-task-unknown-domain-rejected"
GROUP = "error-semantics"
SERVICES = ["swf"]


# timing:real-time — lease: 60 s https://docs.aws.amazon.com/amazonswf/latest/apireference/API_PollForDecisionTask.html
@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """PollForDecisionTask on a never-registered domain returns an empty long-poll response (no taskToken), not
    UnknownResourceFault, while a poll on a registered domain with a scheduled task returns its taskToken."""
    swf = ctx.client("swf")
    # PollForDecisionTask is a server-side long poll that can legitimately take up to ~60s to return
    # an empty response, right on the edge of botocore's default socket read timeout (60s) -- which
    # can trip a spurious client-side ReadTimeoutError that then gets retried repeatedly by the
    # default Config (max_attempts=8). Use a read timeout comfortably longer than the server's
    # long-poll window and a single attempt, for the poll calls specifically.
    swf_poll = ctx.client(
        "swf", config=Config(read_timeout=75, connect_timeout=10, retries={"max_attempts": 1})
    )
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

    # Positive control: with a decision task genuinely scheduled, polling the real domain/taskList
    # returns a non-empty taskToken (not an UnknownResourceFault, not an empty timeout response).
    # Each PollForDecisionTask call is itself a server-side long poll that can legitimately return
    # empty if the task isn't assignable yet right after StartWorkflowExecution, so retry a bounded
    # number of times rather than treating one empty response as failure.
    wf_id = ctx.unique_name("sim2real-behav-wf-")
    swf.start_workflow_execution(
        domain=domain, workflowId=wf_id, workflowType={"name": wt_name, "version": "1.0"}
    )
    ctx.on_cleanup(lambda: _best_effort_terminate(swf, domain, wf_id))

    poll = _poll_decision_task(swf_poll, domain, tasklist)
    assert poll.get("taskToken"), "expected a decision task to be assignable for a freshly started workflow"

    # A domain name that was NEVER registered still returns an empty (no taskToken) long-poll
    # response, not UnknownResourceFault -- distinct from the correctly-scheduled poll above.
    bogus_domain = ctx.unique_name("sim2real-behav-nodomain-")
    bogus_poll = swf_poll.poll_for_decision_task(domain=bogus_domain, taskList={"name": tasklist})
    assert not bogus_poll.get("taskToken"), f"unexpected taskToken from unknown domain: {bogus_poll!r}"


def _poll_decision_task(swf, domain, tasklist, attempts=3):
    task = {}
    for _ in range(attempts):
        task = swf.poll_for_decision_task(domain=domain, taskList={"name": tasklist})
        if task.get("taskToken"):
            return task
        time.sleep(1)
    return task


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

