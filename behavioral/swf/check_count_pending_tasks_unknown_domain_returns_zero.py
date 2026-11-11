"""count-pending-tasks-unknown-domain-returns-zero."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "count-pending-tasks-unknown-domain-returns-zero"
GROUP = "error-semantics"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CountPendingActivityTasks and CountPendingDecisionTasks return count 0, not UnknownResourceFault, for an
    unused task list in a registered, a never-registered and a deprecated domain."""
    swf = ctx.client("swf")
    domain = ctx.unique_name("sim2real-behav-swfcnt-")
    swf.register_domain(
        name=domain,
        workflowExecutionRetentionPeriodInDays="1",
        tags=[{"key": "env", "value": "sim2real"}],
    )
    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
    ctx.on_cleanup(lambda: swf.deprecate_domain(name=domain))
    task_list = {"name": ctx.unique_name("sim2real-behav-tl-")}

    # positive control: a real, empty task list on a real, ACTIVE domain returns count=0
    act_count = swf.count_pending_activity_tasks(domain=domain, taskList=task_list)
    assert act_count["count"] == 0, f"expected count=0 for an unused task list, got {act_count}"
    dec_count = swf.count_pending_decision_tasks(domain=domain, taskList=task_list)
    assert dec_count["count"] == 0, f"expected count=0 for an unused task list, got {dec_count}"

    # a domain name that was never registered in this account: not validated here, returns 0
    missing_domain = ctx.unique_name("sim2real-behav-nodomain-")
    never_registered_act = swf.count_pending_activity_tasks(domain=missing_domain, taskList=task_list)
    assert never_registered_act["count"] == 0, never_registered_act
    never_registered_dec = swf.count_pending_decision_tasks(domain=missing_domain, taskList=task_list)
    assert never_registered_dec["count"] == 0, never_registered_dec

    # a domain that WAS registered and then deprecated: still no domain-state validation
    # on this read path either -- also returns count=0, never UnknownResourceFault
    deprecated_domain = ctx.unique_name("sim2real-behav-swfcntdep-")
    swf.register_domain(
        name=deprecated_domain,
        workflowExecutionRetentionPeriodInDays="1",
        tags=[{"key": "env", "value": "sim2real"}],
    )
    swf.deprecate_domain(name=deprecated_domain)

    deprecated_act = swf.count_pending_activity_tasks(domain=deprecated_domain, taskList=task_list)
    assert deprecated_act["count"] == 0, deprecated_act

    deprecated_dec = swf.count_pending_decision_tasks(domain=deprecated_domain, taskList=task_list)
    assert deprecated_dec["count"] == 0, deprecated_dec


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
