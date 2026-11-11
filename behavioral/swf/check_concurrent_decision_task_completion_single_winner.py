"""concurrent-decision-task-completion-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-decision-task-completion-single-winner"
GROUP = "concurrency"
SERVICES = ["swf"]


# timing:real-time — lease: 60 s https://docs.aws.amazon.com/amazonswf/latest/apireference/API_PollForDecisionTask.html
@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Only one of several concurrent PollForDecisionTask callers gets a usable taskToken
    for the single scheduled decision task, and re-using that token to complete the
    decision a second time (simulating a would-be second winner) is rejected."""
    swf = ctx.client("swf")
    # SWF long-polls block server-side for up to 60s; AWS recommends a socket read
    # timeout of >= 70s for Poll* calls so the client doesn't time out (and the
    # default "standard" retry mode doesn't stack repeated 60s waits into a hang)
    # before the server responds with an empty ("no task") result. Build a second
    # client that shares the runner's creds/endpoint but with a longer read timeout
    # and a single attempt, dedicated to the racing long-polls.
    poll_swf = _poll_client(ctx)
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-swf-cdt-tl-")
    workflow_id = ctx.unique_name("sim2real-swf-cdt-wf-")
    wf_name = ctx.unique_name("sim2real-swf-cdt-wftype-")
    wf_version = "1.0"

    swf.register_workflow_type(
        domain=domain,
        name=wf_name,
        version=wf_version,
        defaultTaskList={"name": task_list},
        # Generous headroom: two of the three concurrent long-poll callers below may each
        # block for up to ~75s (server-side long poll + our client's read timeout) before
        # returning empty, and ThreadPoolExecutor.map only returns once ALL three finish --
        # so the winner's decision task must still be valid (not yet DecisionTaskTimedOut)
        # by the time we get around to responding to it.
        defaultTaskStartToCloseTimeout="300",
        defaultExecutionStartToCloseTimeout="600",
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", {"name": wf_name, "version": wf_version}))

    run_id = swf.start_workflow_execution(
        domain=domain,
        workflowId=workflow_id,
        workflowType={"name": wf_name, "version": wf_version},
        taskList={"name": task_list},
    )["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}
    ctx.on_cleanup(
        lambda: _safe(
            lambda: swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id)
        )
    )

    # Exactly one decision task is scheduled (WorkflowExecutionStarted). Race several
    # concurrent long-poll callers against it. SWF's contract (documented explicitly by
    # AWS: "it is possible, but unlikely, for a decision task to be dispatched to more
    # than one decider") is that AT MOST one RespondDecisionTaskCompleted for that task
    # ever succeeds -- any decider that "lost the race" gets a taskToken that a later
    # response call to it must reject. So: collect every non-empty taskToken handed out,
    # try to complete with each in turn, and assert exactly one succeeds while the rest
    # (if any) are rejected as an unknown/stale decision task.
    def _poll():
        return poll_swf.poll_for_decision_task(domain=domain, taskList={"name": task_list})

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: _poll(), range(3)))

    candidates = [r["taskToken"] for r in results if r.get("taskToken")]
    empties = [r for r in results if not r.get("taskToken")]
    assert len(candidates) >= 1, "expected at least one poller to receive the decision task"
    assert len(candidates) + len(empties) == 3, (
        f"expected every poller result to be either a candidate or empty, "
        f"got {len(candidates)} candidate(s) and {len(empties)} empt(y/ies) of 3 results"
    )

    # The exact message SWF returns for a decision task token whose execution is closed.
    stale_message = (
        f"Unknown execution: WorkflowExecution=[workflowId={workflow_id}, runId={run_id}]"
    )
    successes = []
    rejections = []
    for token in candidates:
        try:
            _respond_with_retry(swf, token)
            successes.append(token)
        except Exception as err:
            rejections.append((token, _client_error(err)))

    assert len(successes) == 1, (
        f"expected exactly one winning RespondDecisionTaskCompleted, got {len(successes)} "
        f"of {len(candidates)} candidate taskToken(s)"
    )
    for _, (code, message) in rejections:
        assert code == "UnknownResourceFault", f"expected UnknownResourceFault, got {code}"
        assert message == stale_message, f"expected message {stale_message!r}, got {message!r}"

    winner_token = successes[0]

    # A second, would-be "other winner" completion attempt using the SAME (already
    # consumed) winning token is also rejected: the task stays consumed, it never
    # flips back open for a duplicate completion.
    code, message = _error(
        lambda: swf.respond_decision_task_completed(
            taskToken=winner_token,
            decisions=[
                {
                    "decisionType": "CompleteWorkflowExecution",
                    "completeWorkflowExecutionDecisionAttributes": {"result": "double-submit"},
                }
            ],
        )
    )
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault, got {code}"
    assert message == stale_message, f"expected message {stale_message!r}, got {message!r}"

    # Effect check: the execution closed exactly once as COMPLETED, not duplicated.
    history = swf.get_workflow_execution_history(domain=domain, execution=execution)["events"]
    completed_events = [e for e in history if e["eventType"] == "WorkflowExecutionCompleted"]
    assert len(completed_events) == 1, f"expected exactly one completion event, got {len(completed_events)}"


def _respond_with_retry(swf, token, attempts: int = 6, delay: float = 2.0) -> None:
    """RespondDecisionTaskCompleted for a freshly-delivered token, with a short bounded
    retry on UnknownResourceFault -- SWF's DecisionTaskStarted bookkeeping for a just
    -delivered task can lag the PollForDecisionTask response by a beat, so a completion
    attempted immediately after can transiently 404 before it settles."""
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            swf.respond_decision_task_completed(
                taskToken=token,
                decisions=[
                    {
                        "decisionType": "CompleteWorkflowExecution",
                        "completeWorkflowExecutionDecisionAttributes": {"result": "done"},
                    }
                ],
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "UnknownResourceFault":
                raise
            last_err = err
            time.sleep(delay)
    raise last_err


def _poll_client(ctx):
    """An SWF client on the runner's target with a read timeout long enough to cover an SWF
    long poll (server-side up to 60s) and a single attempt, so a losing poller's empty
    ("no task") response isn't misread as a transient failure and retried into a hang."""
    from botocore.config import Config

    return ctx.client(
        "swf", config=Config(read_timeout=75, connect_timeout=10, retries={"max_attempts": 1})
    )


def _safe(fn) -> None:
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
    """Call fn(); return its botocore error (code, message). A SUCCESS raises: a consumed
    decision task accepting a second completion is the defect this check exists to catch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return _client_error(err)
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _client_error(err):
    from botocore.exceptions import ClientError

    if isinstance(err, ClientError):
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise err


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
