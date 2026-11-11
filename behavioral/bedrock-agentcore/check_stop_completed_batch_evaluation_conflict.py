"""stop-completed-batch-evaluation-conflict."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-completed-batch-evaluation-conflict"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]

_TERMINAL_STATUSES = {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "STOPPED"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopBatchEvaluation succeeds on a running batch evaluation, and a second stop on the
    terminal job is refused with ConflictException and the exact concurrent-modification message,
    leaving its status unchanged.
    """
    agentcore = ctx.client("bedrock-agentcore")
    logs = ctx.client("logs")
    name = _alnum_name("Sim2realBatchEval")

    # StartBatchEvaluation validates that the CloudWatch log group actually exists (it
    # returns ValidationException("Log group '...' not found") otherwise), so a real
    # (empty) log group is provisioned here even though no sessions need to be found --
    # the check only needs the job to start, then be stopped twice.
    log_group_name = f"/sim2real/behav-{ctx.unique_name('batcheval-')}"
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _best_effort_delete_log_group(logs, log_group_name))

    data_source_config = {
        "cloudWatchLogs": {
            "serviceNames": ["Sim2realBehavAgent.DEFAULT"],
            "logGroupNames": [log_group_name],
        }
    }
    started = agentcore.start_batch_evaluation(
        batchEvaluationName=name,
        dataSourceConfig=data_source_config,
        evaluators=[{"evaluatorId": "Builtin.GoalSuccessRate"}],
        tags={"sim2real": CHECK},
    )
    batch_evaluation_id = started["batchEvaluationId"]
    ctx.on_cleanup(lambda: _best_effort_delete_batch_evaluation(agentcore, batch_evaluation_id))

    # Positive control: stopping right after start (job is not yet terminal) succeeds.
    stop_resp = agentcore.stop_batch_evaluation(batchEvaluationId=batch_evaluation_id)
    assert stop_resp["batchEvaluationId"] == batch_evaluation_id

    stopped_status = _wait_for_status(agentcore, batch_evaluation_id, _TERMINAL_STATUSES, timeout_s=120)
    assert stopped_status in _TERMINAL_STATUSES

    # Primary assertion: stopping an already-terminal batch evaluation is rejected.
    code, message = _error(lambda: agentcore.stop_batch_evaluation(batchEvaluationId=batch_evaluation_id))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == (
        "Failed to update the resource as a concurrent request modified the resource. "
        "Retry the request after the other request has completed."
    ), f"expected the exact conflict message, got {message!r}"

    # Effect absent: status did not change as a result of the rejected second stop.
    status_after = agentcore.get_batch_evaluation(batchEvaluationId=batch_evaluation_id)["status"]
    assert status_after == stopped_status, (
        f"status changed after a rejected stop: {stopped_status} -> {status_after}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _alnum_name(prefix: str) -> str:
    suffix = str(int(time.time() * 1000))[-10:]
    return f"{prefix}{suffix}"


def _wait_for_status(agentcore, batch_evaluation_id: str, target_statuses: set, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = ""
    while time.monotonic() < deadline:
        status = agentcore.get_batch_evaluation(batchEvaluationId=batch_evaluation_id)["status"]
        if status in target_statuses:
            return status
        time.sleep(3)
    raise AssertionError(f"batch evaluation {batch_evaluation_id} never reached {target_statuses} (last={status})")


def _best_effort_delete_batch_evaluation(agentcore, batch_evaluation_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        agentcore.delete_batch_evaluation(batchEvaluationId=batch_evaluation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_delete_log_group(logs, log_group_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
