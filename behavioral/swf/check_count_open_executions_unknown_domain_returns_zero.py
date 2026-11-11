"""count-open-executions-unknown-domain-returns-zero."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "count-open-executions-unknown-domain-returns-zero"
GROUP = "error-semantics"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CountOpenWorkflowExecutions returns count 0, not UnknownResourceFault, for an empty registered domain,
    a domain name never registered, and a deprecated domain: this read path does not validate the domain."""
    swf = ctx.client("swf")
    domain = ctx.unique_name("sim2real-behav-swfopen-")
    swf.register_domain(name=domain, workflowExecutionRetentionPeriodInDays="1")
    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
    ctx.on_cleanup(lambda: swf.deprecate_domain(name=domain))

    start_time_filter = {"oldestDate": dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)}

    # positive control: valid, ACTIVE domain with no open executions returns count=0, no fault
    ok = swf.count_open_workflow_executions(domain=domain, startTimeFilter=start_time_filter)
    assert ok["count"] == 0, ok

    # a domain name that was never registered at all: SWF does NOT validate domain
    # existence on this read path, and simply returns an empty count
    missing_domain = ctx.unique_name("sim2real-behav-nodomain-")
    never_registered = swf.count_open_workflow_executions(
        domain=missing_domain, startTimeFilter=start_time_filter
    )
    assert never_registered["count"] == 0, never_registered

    # a domain that WAS registered, then deprecated: still no domain-state validation on
    # this read path either -- also returns count=0, never UnknownResourceFault
    deprecated_domain = ctx.unique_name("sim2real-behav-swfopendep-")
    swf.register_domain(name=deprecated_domain, workflowExecutionRetentionPeriodInDays="1")
    swf.deprecate_domain(name=deprecated_domain)
    deprecated_result = swf.count_open_workflow_executions(
        domain=deprecated_domain, startTimeFilter=start_time_filter
    )
    assert deprecated_result["count"] == 0, deprecated_result


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
