"""poll-for-decision-task-limit-exceeded-error."""
from __future__ import annotations

import threading
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "poll-for-decision-task-limit-exceeded-error"
GROUP = "error-semantics"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c6", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """1,001 concurrent PollForDecisionTask calls on one task list, one more than the documented 1,000 pollers per
    task list, make the excess fail with LimitExceededFault and its exact message, never OperationNotPermittedFault."""
    domain = _shared_domain(ctx)
    task_list = ctx.unique_name("sim2real-behav-tl-")

    num_pollers = 1001  # one more than the documented hard cap of 1,000 simultaneous pollers
    # one shared, thread-safe client whose connection pool holds every long poll open at once
    poller = ctx.client("swf", config=Config(max_pool_connections=num_pollers + 16))
    results: list[str] = []
    lock = threading.Lock()
    limit_errors: list = []
    found_limit = threading.Event()
    stop_waiting = threading.Event()  # the fault was seen or every poller has returned
    # every poller waits here so the requests go out together, not spread over thread creation
    start = threading.Barrier(num_pollers + 1)

    def _poll(idx: int) -> None:
        try:
            start.wait(timeout=120)
        except threading.BrokenBarrierError:
            return
        try:
            poller.poll_for_decision_task(
                domain=domain, taskList={"name": task_list}, identity=f"poller-{idx}"
            )
            code = "OK"
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "LimitExceededFault":
                with lock:
                    limit_errors.append(exc.response["Error"])
        except Exception:  # pragma: no cover - transport hiccups under heavy concurrency
            code = "TRANSPORT_ERROR"
        with lock:
            results.append(code)
            if len(results) == num_pollers:
                stop_waiting.set()
        if code == "LimitExceededFault":
            found_limit.set()
            stop_waiting.set()

    # The wait below stays inside the runner's budget so a miss fails with this check's own
    # message rather than as a runner timeout.
    budget = 62.0
    time_left = ctx.time_left()
    if time_left is not None:
        budget = min(budget, time_left - 3.0)
    assert budget >= 10.0, (
        f"only {time_left:.0f}s of the check budget remain after setup, too little to open "
        f"{num_pollers} pollers and wait for the cap's rejection"
    )

    threads: list[threading.Thread] = []
    # A small stack keeps 1,001 pollers cheap; the stack size is process-wide, so the previous size
    # is put back once they have started.
    try:
        prev_stack_size = threading.stack_size(64 * 1024)
    except (ValueError, RuntimeError):
        prev_stack_size = None
    try:
        for i in range(num_pollers):
            t = threading.Thread(target=_poll, args=(i,), daemon=True)
            t.start()
            threads.append(t)
    except OSError as exc:
        start.abort()
        raise AssertionError(
            f"could not open {num_pollers} concurrent poller threads/connections in this "
            f"environment ({exc}); OS thread/file-descriptor limits prevent exercising the "
            "1,000-poller cap here"
        )
    finally:
        if prev_stack_size is not None:
            threading.stack_size(prev_stack_size)

    # rejections of over-quota pollers are returned promptly (no long-poll wait involved), so a
    # deadline bounded on wall-clock time -- not an unconditional sleep -- is enough to let them
    # land; pollers that are accepted keep long-polling until SWF's own timeout, so we do not wait
    # for every thread to finish, only until the fault is seen or the deadline passes.
    deadline = time.monotonic() + budget
    try:
        start.wait(timeout=max(0.0, deadline - time.monotonic()))
    except threading.BrokenBarrierError:
        raise AssertionError(
            f"the {num_pollers} poller threads did not all start before the deadline, so the "
            "1,000-poller cap could not be exercised here"
        ) from None
    stop_waiting.wait(timeout=max(0.0, deadline - time.monotonic()))
    for t in threads:
        remaining = deadline - time.monotonic()
        if found_limit.is_set() or remaining <= 0:
            break
        t.join(timeout=remaining)
    with lock:
        collected = list(results)
        limit_seen = list(limit_errors)

    codes_seen = {c for c in collected if c != "OK"}
    assert "LimitExceededFault" in codes_seen, (
        f"expected at least one PollForDecisionTask call to be rejected with "
        f"LimitExceededFault after opening {num_pollers} concurrent pollers on one task "
        f"list ({len(collected)} of {num_pollers} calls returned so far); codes seen: {codes_seen}"
    )
    assert limit_seen and all(
        err.get("Message") == "Limit on maximum concurrent poll requests per task list reached"
        for err in limit_seen
    ), limit_seen
    assert "OperationNotPermittedFault" not in codes_seen, (
        "over-quota poller rejection must be LimitExceededFault, not OperationNotPermittedFault"
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
