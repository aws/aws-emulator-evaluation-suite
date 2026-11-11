"""count-pending-tasks-unknown-tasklist-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "count-pending-tasks-unknown-tasklist-error"
GROUP = "error-semantics"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CountPendingActivityTasks and CountPendingDecisionTasks return count 0 for a task list in a domain that was
    never registered, the same as for an unused task list in a registered domain, not UnknownResourceFault."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    tasklist = {"name": ctx.unique_name("sim2real-behav-tl-unused-")}

    # Positive control: a real domain with an unused task list returns a zero count, not an error.
    activity_count = swf.count_pending_activity_tasks(domain=domain, taskList=tasklist)
    assert activity_count["count"] == 0, f"expected count=0 for an unused task list, got {activity_count}"
    decision_count = swf.count_pending_decision_tasks(domain=domain, taskList=tasklist)
    assert decision_count["count"] == 0, f"expected count=0 for an unused task list, got {decision_count}"

    # A domain name that was NEVER registered still returns a zero count, not UnknownResourceFault.
    bogus_domain = ctx.unique_name("sim2real-behav-nodomain-")
    bogus_activity_count = swf.count_pending_activity_tasks(domain=bogus_domain, taskList=tasklist)
    assert bogus_activity_count["count"] == 0, (
        f"expected count=0 for a never-registered domain, not UnknownResourceFault, got {bogus_activity_count}"
    )
    bogus_decision_count = swf.count_pending_decision_tasks(domain=bogus_domain, taskList=tasklist)
    assert bogus_decision_count["count"] == 0, (
        f"expected count=0 for a never-registered domain, not UnknownResourceFault, got {bogus_decision_count}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

