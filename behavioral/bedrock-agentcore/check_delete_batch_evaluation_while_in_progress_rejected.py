"""delete-batch-evaluation-while-in-progress-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-batch-evaluation-while-in-progress-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]

_MANAGED_TAG_KEY = "sim2real:managed"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBatchEvaluation on a non-terminal job is refused with ConflictException and leaves it
    in place; once stopped the same job deletes (positive control), and a second delete of the
    id is refused with ResourceNotFoundException rather than accepted."""
    client = ctx.client("bedrock-agentcore")
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("/sim2real/bedrock-agentcore-behav")
    logs.create_log_group(logGroupName=log_group_name, tags={_MANAGED_TAG_KEY: "true"})
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    # Hold the in-progress window: each attempt starts a fresh job and reads it back; the
    # delete is issued only against a job the service still reports as non-terminal. A job
    # that already finished is discarded and replaced, up to a bounded number of attempts.
    batch_id = None
    held_status = None
    for attempt in range(_HOLD_ATTEMPTS):
        name = _sanitize(ctx.unique_name(f"sim2realbatchneg{attempt}"))
        started = client.start_batch_evaluation(
            batchEvaluationName=name,
            dataSourceConfig={
                "cloudWatchLogs": {
                    "serviceNames": ["sim2real-test-service"],
                    "logGroupNames": [log_group_name],
                }
            },
            evaluators=[{"evaluatorId": "Builtin.Helpfulness"}],
            tags={_MANAGED_TAG_KEY: "true"},
        )
        candidate = started["batchEvaluationId"]
        ctx.on_cleanup(lambda bid=candidate: _best_effort_teardown(client, bid))
        assert started["status"] in ("PENDING", "IN_PROGRESS"), (
            f"expected a freshly started batch evaluation to be PENDING or IN_PROGRESS, "
            f"got {started['status']!r}"
        )
        current = client.get_batch_evaluation(batchEvaluationId=candidate)
        if current["status"] not in _TERMINAL:
            batch_id = candidate
            held_status = current["status"]
            break
    if batch_id is None:
        raise AssertionError(
            f"no batch evaluation stayed non-terminal long enough to delete in {_HOLD_ATTEMPTS} attempts"
        )

    # Negative: deleting while the job is still active is a state conflict.
    code, message = _error(lambda: client.delete_batch_evaluation(batchEvaluationId=batch_id))
    assert code == "ConflictException", (
        f"expected ConflictException deleting an active batch evaluation, got {code!r}"
    )
    # The refusal names the status the job is in at the delete: the one read just above, or the
    # later non-terminal status a PENDING job can move to before the delete lands.
    statuses = (held_status, "IN_PROGRESS") if held_status == "PENDING" else (held_status,)
    expected_messages = {
        f"Cannot delete batch evaluation in status {status}. Only COMPLETED, "
        "COMPLETED_WITH_ERRORS, FAILED, or STOPPED evaluations can be deleted."
        for status in statuses
    }
    assert message in expected_messages, f"unexpected ConflictException message {message!r}"

    # Effect absent: the job is untouched and still retrievable.
    still_there = client.get_batch_evaluation(batchEvaluationId=batch_id)
    assert still_there["batchEvaluationId"] == batch_id, (
        f"expected the rejected delete to leave {batch_id!r} in place, "
        f"got {still_there['batchEvaluationId']!r}"
    )

    # Positive control: once stopped (or otherwise reaches a terminal state -- with no
    # real sessions to discover, the job can race to COMPLETED around the same moment we
    # call Stop, which the service reports as ConflictException on Stop itself), the same
    # job can be deleted successfully.
    stopped = _stop_and_await_terminal(client, batch_id)
    assert stopped["status"] in ("STOPPED", "COMPLETED", "COMPLETED_WITH_ERRORS"), (
        f"expected the batch evaluation to reach a terminal state before delete, "
        f"got {stopped['status']!r}"
    )

    client.delete_batch_evaluation(batchEvaluationId=batch_id)
    final_code, final_message = _error(lambda: client.get_batch_evaluation(batchEvaluationId=batch_id))
    assert final_code == "ResourceNotFoundException", (
        f"expected GetBatchEvaluation to 404 after delete, got {final_code!r}"
    )
    assert final_message == _NOT_FOUND_MESSAGE, (
        f"unexpected GetBatchEvaluation message {final_message!r}"
    )

    # Deletes prove gone AND unusable: a mutation on the now-dead id is rejected too, not
    # silently accepted a second time.
    redelete_code, redelete_message = _error(
        lambda: client.delete_batch_evaluation(batchEvaluationId=batch_id)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second delete of {batch_id!r} to 404, not succeed or conflict, "
        f"got {redelete_code!r}"
    )
    assert redelete_message == _NOT_FOUND_MESSAGE, (
        f"unexpected DeleteBatchEvaluation message {redelete_message!r}"
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


_HOLD_ATTEMPTS = 3

_NOT_FOUND_MESSAGE = (
    "Failed to retrieve the resource because it doesn't exist. "
    "Retry the request with a different resource identifier."
)

_TERMINAL = ("STOPPED", "COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED")


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
