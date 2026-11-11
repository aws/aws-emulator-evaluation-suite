"""concurrent-activity-pollers-no-duplicate-delivery."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-activity-pollers-no-duplicate-delivery"
GROUP = "concurrency"
SERVICES = ["swf"]


# timing:real-time — lease: 60 s https://docs.aws.amazon.com/amazonswf/latest/apireference/API_PollForActivityTask.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Multiple simultaneous PollForActivityTask callers on the same task list are
    dispatched disjoint tasks; the single outstanding activity task is delivered to
    exactly one poller, never to two."""
    swf = ctx.client("swf")
    # PollForActivityTask/PollForDecisionTask are server-side long polls that can
    # legitimately take up to ~60s to return an empty response -- right on the edge
    # of botocore's default socket read timeout (60s), which can trip a spurious
    # client-side ReadTimeoutError that then gets retried repeatedly. Poll through a
    # target-wired client with a read timeout comfortably longer than the server's
    # long-poll window and a single attempt.
    poll_swf = ctx.client(
        "swf", config=Config(read_timeout=75, connect_timeout=10, retries={"max_attempts": 1})
    )

    def _poll_client():
        return poll_swf

    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-tl-")
    wf_type = _register_workflow_type(ctx, domain, task_list)
    act_type = _register_activity_type(ctx, domain, task_list)

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    _start_workflow(ctx, domain, workflow_id, wf_type, task_list)

    dtask = _poll_decision_until_task(_poll_client(), domain, task_list)
    swf.respond_decision_task_completed(
        taskToken=dtask["taskToken"],
        decisions=[
            {
                "decisionType": "ScheduleActivityTask",
                "scheduleActivityTaskDecisionAttributes": {
                    "activityType": {"name": act_type[0], "version": act_type[1]},
                    "activityId": "act-1",
                    "taskList": {"name": task_list},
                    "scheduleToStartTimeout": "60",
                    "scheduleToCloseTimeout": "120",
                    "startToCloseTimeout": "60",
                    "heartbeatTimeout": "60",
                },
            }
        ],
    )

    # Warm up: make sure the activity task is actually scheduled before firing the
    # concurrent race, so the race measures dispatch dedup rather than
    # decision-processing propagation lag.
    _wait_for_pending_activity(swf, domain, task_list)

    n_pollers = 4

    def _poll(_i: int) -> dict[str, Any]:
        client = _poll_client()
        return client.poll_for_activity_task(domain=domain, taskList={"name": task_list})

    with ThreadPoolExecutor(max_workers=n_pollers) as pool:
        results = list(pool.map(_poll, range(n_pollers)))

    non_empty = [r for r in results if r.get("taskToken")]
    assert len(non_empty) == 1, f"expected exactly 1 poller to receive the task, got {len(non_empty)} ({results!r})"
    assert non_empty[0]["activityId"] == "act-1", f"expected activityId 'act-1', got {non_empty[0]['activityId']!r}"

    # Independent side-channel: the server's own pending-task bookkeeping must agree
    # that the single task was dispatched and none remain outstanding, rather than
    # trusting only the pollers' own responses (which would be a tautology once
    # exactly one poller is already known to have gotten a token).
    _assert_no_pending_activity(swf, domain, task_list)


def _wait_for_pending_activity(swf, domain: str, task_list: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        count = swf.count_pending_activity_tasks(domain=domain, taskList={"name": task_list})
        if count.get("count", 0) >= 1:
            return
        time.sleep(1)
    # Not fatal -- fall through and let the race itself surface any real dispatch issue.


def _assert_no_pending_activity(swf, domain: str, task_list: str, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = swf.count_pending_activity_tasks(domain=domain, taskList={"name": task_list})
        if last.get("count", 0) == 0:
            return
        time.sleep(1)
    raise AssertionError(f"expected 0 pending activity tasks after dispatch, still {last!r} after {timeout_s}s")


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


def _register_activity_type(ctx, domain: str, task_list: str, **overrides: Any) -> tuple[str, str]:
    swf = ctx.client("swf")
    name = ctx.unique_name("sim2real-swf-act-")
    version = "1.0"
    params: dict[str, Any] = dict(
        domain=domain,
        name=name,
        version=version,
        defaultTaskStartToCloseTimeout="60",
        defaultTaskHeartbeatTimeout="60",
        defaultTaskList={"name": task_list},
        defaultTaskScheduleToStartTimeout="60",
        defaultTaskScheduleToCloseTimeout="120",
    )
    params.update(overrides)
    swf.register_activity_type(**params)
    type_ref = {"name": params["name"], "version": params["version"]}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", type_ref))
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


def _poll_decision_until_task(client, domain: str, task_list: str, timeout_s: float = 90.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.poll_for_decision_task(domain=domain, taskList={"name": task_list})
        if resp.get("taskToken"):
            return resp
    raise AssertionError(f"no decision task delivered on {task_list!r} within {timeout_s}s")


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

