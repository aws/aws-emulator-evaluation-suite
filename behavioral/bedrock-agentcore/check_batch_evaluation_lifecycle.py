"""batch-evaluation-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-evaluation-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartBatchEvaluation moves the job out of PENDING, StopBatchEvaluation brings it to a
    terminal state (STOPPED, or COMPLETED when the job wins the race), and
    DeleteBatchEvaluation removes it so GetBatchEvaluation 404s."""
    client = ctx.client("bedrock-agentcore")
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("/sim2real/bedrock-agentcore-behav")
    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    name = _sanitize(ctx.unique_name("sim2realbatch"))
    started = client.start_batch_evaluation(
        batchEvaluationName=name,
        dataSourceConfig={
            "cloudWatchLogs": {
                "serviceNames": ["sim2real-test-service"],
                "logGroupNames": [log_group_name],
            }
        },
        evaluators=[{"evaluatorId": "Builtin.Helpfulness"}],
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    batch_id = started["batchEvaluationId"]
    ctx.on_cleanup(lambda: _best_effort_teardown(client, batch_id))
    assert started["status"] in ("PENDING", "IN_PROGRESS"), (
        f"expected StartBatchEvaluation to report PENDING or IN_PROGRESS, got {started['status']!r}"
    )

    # Give the job a bounded window to leave PENDING before we race a Stop against it;
    # a job that never leaves PENDING within the window is itself a defect, not noise.
    _await_out_of_pending(client, batch_id)

    # With an empty/synthetic log group there are zero real sessions to discover, so the
    # job can legitimately race to a terminal state (COMPLETED) around the same moment we
    # call Stop; the service reports that race as ConflictException on Stop itself, not
    # just on later polls. Either a successful Stop -> STOPPED, or a losing race where the
    # job beat us to COMPLETED, demonstrates the same state-machine property: the job
    # reaches a terminal state promptly and does not hang.
    stopped = _stop_and_await_terminal(client, batch_id)
    assert stopped["status"] in ("STOPPED", "COMPLETED", "COMPLETED_WITH_ERRORS"), (
        f"expected a terminal, non-FAILED status after Stop, got {stopped['status']!r}"
    )
    assert stopped["batchEvaluationId"] == batch_id, (
        f"expected GetBatchEvaluation to echo {batch_id!r}, got {stopped['batchEvaluationId']!r}"
    )

    client.delete_batch_evaluation(batchEvaluationId=batch_id)

    code, message = _error(lambda: client.get_batch_evaluation(batchEvaluationId=batch_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetBatchEvaluation on a deleted batch to 404 with ResourceNotFoundException, got {code!r}"
    )
    assert message == _NOT_FOUND_MESSAGE, f"unexpected GetBatchEvaluation message {message!r}"

    # The delete must also make the id unusable, not merely unreadable: a mutating call
    # against the same dead id must fail the same way an independent read does.
    stop_code, stop_message = _error(lambda: client.stop_batch_evaluation(batchEvaluationId=batch_id))
    assert stop_code == "ResourceNotFoundException", (
        f"expected StopBatchEvaluation on a deleted batch to 404 with ResourceNotFoundException, "
        f"got {stop_code!r}"
    )
    assert stop_message == _NOT_FOUND_MESSAGE, (
        f"unexpected StopBatchEvaluation message {stop_message!r}"
    )


# ===== helpers =====
def _sanitize(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c == "_" else "" for c in name)
    if not cleaned[:1].isalpha():
        cleaned = "b" + cleaned
    return cleaned[:48]


def _best_effort(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_teardown(client, batch_id: str) -> None:
    # Stop answers ConflictException on a job already terminal; delete answers it until the job
    # is terminal, so the delete retries that code alone.
    from botocore.exceptions import ClientError

    try:
        client.stop_batch_evaluation(batchEvaluationId=batch_id)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            client.delete_batch_evaluation(batchEvaluationId=batch_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
        time.sleep(2)
    _best_effort(lambda: client.delete_batch_evaluation(batchEvaluationId=batch_id))


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. A call that
    succeeds raises AssertionError, so an accepted call never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


_NOT_FOUND_MESSAGE = (
    "Failed to retrieve the resource because it doesn't exist. "
    "Retry the request with a different resource identifier."
)

_TERMINAL = ("STOPPED", "COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED")


def _await_out_of_pending(client, batch_id: str, *, timeout_s=30.0, interval_s=2.0):
    return _poll_until(
        lambda: client.get_batch_evaluation(batchEvaluationId=batch_id),
        lambda r: r["status"] != "PENDING",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _stop_and_await_terminal(client, batch_id: str, *, timeout_s=90.0, interval_s=3.0):
    """Calls StopBatchEvaluation, tolerating a ConflictException that means the job won
    the race to a terminal state on its own; either way, waits for -- and returns -- the
    batch evaluation once it is terminal."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.stop_batch_evaluation(batchEvaluationId=batch_id)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException":
                raise
            current = client.get_batch_evaluation(batchEvaluationId=batch_id)
            if current["status"] in _TERMINAL:
                return current
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

    return _poll_until(
        lambda: client.get_batch_evaluation(batchEvaluationId=batch_id),
        lambda r: r["status"] in _TERMINAL,
        timeout_s=max(5.0, deadline - time.monotonic()),
        interval_s=interval_s,
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
