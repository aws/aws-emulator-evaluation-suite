"""concurrent-decision-pollers-no-duplicate-delivery."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-decision-pollers-no-duplicate-delivery"
GROUP = "concurrency"
SERVICES = ["swf"]


# timing:real-time — lease: 60 s https://docs.aws.amazon.com/amazonswf/latest/apireference/API_PollForDecisionTask.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Multiple simultaneous long-poll PollForDecisionTask callers on the same task
    list never receive the same taskToken twice; exactly one poller gets the single
    outstanding decision task, the rest time out with an empty taskToken."""
    swf = ctx.client("swf")
    # PollForDecisionTask is a server-side long poll that can legitimately take up to
    # ~60s to return an empty response -- right on the edge of botocore's default
    # socket read timeout (60s), which can trip a spurious client-side
    # ReadTimeoutError that then gets retried. Poll through a target-wired client with
    # a read timeout comfortably longer than the server's long-poll window and a
    # single attempt.
    poll_swf = ctx.client(
        "swf", config=Config(read_timeout=75, connect_timeout=10, retries={"max_attempts": 1})
    )

    def _poll_client():
        return poll_swf

    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    # Use a decision-task startToCloseTimeout well beyond the race's long-poll window
    # (each poll client can legitimately block ~60-75s). Otherwise the winning
    # poller's un-responded task can itself time out mid-race and get RESCHEDULED as
    # a brand-new decision task (distinct taskToken) to one of the still-waiting
    # pollers -- that's real DecisionTaskTimedOut/reschedule behavior (covered by its
    # own check), not a same-task duplicate-delivery bug, and would make this check
    # flaky/wrong.
    wf_type = _register_workflow_type(ctx, domain, task_list, defaultTaskStartToCloseTimeout="300")

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    _start_workflow(ctx, domain, workflow_id, wf_type, task_list)

    # Warm up: make sure the initial decision task is actually scheduled (not just
    # that StartWorkflowExecution returned) before firing the concurrent race, so the
    # race measures dispatch dedup rather than execution-creation propagation lag.
    _wait_for_pending_decision(swf, domain, task_list)

    n_pollers = 4

    def _poll(_i: int) -> dict[str, Any]:
        client = _poll_client()
        return client.poll_for_decision_task(domain=domain, taskList={"name": task_list})

    with ThreadPoolExecutor(max_workers=n_pollers) as pool:
        results = list(pool.map(_poll, range(n_pollers)))

    non_empty = [r for r in results if r.get("taskToken")]
    assert len(non_empty) == 1, f"expected exactly 1 poller to receive the task, got {len(non_empty)} ({results!r})"
    assert non_empty[0]["workflowExecution"]["workflowId"] == workflow_id, (
        f"expected the delivered task to belong to {workflow_id!r}, "
        f"got {non_empty[0]['workflowExecution']!r}"
    )
    tokens = {r["taskToken"] for r in non_empty}
    assert len(tokens) == 1, f"expected the single delivered task to carry one distinct taskToken, got {tokens!r}"

    # Independent side-channel: the 4 PollForDecisionTask calls above are the mutating calls under
    # test, so confirm the consequence through a DIFFERENT operation -- the dispatched task actually
    # left the pending queue, rather than trusting only the winning poller's own response.
    remaining = _wait_for_no_pending_decision(swf, domain, task_list)
    assert remaining == 0, f"expected the dispatched decision task to leave the pending queue, still {remaining} pending"


def _wait_for_pending_decision(swf, domain: str, task_list: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        count = swf.count_pending_decision_tasks(domain=domain, taskList={"name": task_list})
        if count.get("count", 0) >= 1:
            return
        time.sleep(1)
    # Not fatal -- fall through and let the race itself surface any real dispatch issue.


def _wait_for_no_pending_decision(swf, domain: str, task_list: str, timeout_s: float = 10.0) -> int:
    deadline = time.monotonic() + timeout_s
    last = 1
    while time.monotonic() < deadline:
        count = swf.count_pending_decision_tasks(domain=domain, taskList={"name": task_list})
        last = count.get("count", 0)
        if last == 0:
            return 0
        time.sleep(1)
    return last


def _register_workflow_type(ctx, domain: str, task_list: str, **overrides: Any) -> tuple[str, str]:
    swf = ctx.client("swf")
    name = ctx.unique_name("sim2real-swf-wft-")
    version = "1.0"
    params: dict[str, Any] = dict(
        domain=domain,
        name=name,
        version=version,
        defaultTaskStartToCloseTimeout="30",
        defaultExecutionStartToCloseTimeout="300",
        defaultTaskList={"name": task_list},
        defaultChildPolicy="TERMINATE",
    )
    params.update(overrides)
    swf.register_workflow_type(**params)
    type_ref = {"name": params["name"], "version": params["version"]}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", type_ref))
    return name, version


def _start_workflow(
    ctx, domain: str, workflow_id: str, wf_type: tuple[str, str], task_list: str, **overrides: Any
) -> str:
    swf = ctx.client("swf")
    params: dict[str, Any] = dict(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_type[0], "version": wf_type[1]},
        taskList={"name": task_list},
        tagList=["sim2real:" + CHECK],
    )
    params.update(overrides)
    resp = swf.start_workflow_execution(**params)
    run_id = resp["runId"]

    def _cleanup():
        try:
            swf.terminate_workflow_execution(
                domain=domain, workflowId=workflow_id, runId=run_id, reason="test-cleanup"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UnknownResourceFault":
                raise

    ctx.on_cleanup(_cleanup)
    return run_id


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
