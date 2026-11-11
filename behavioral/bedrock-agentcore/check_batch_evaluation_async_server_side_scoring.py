"""batch-evaluation-async-server-side-scoring."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-evaluation-async-server-side-scoring"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

_NON_TERMINAL = {"PENDING", "IN_PROGRESS", "STOPPING"}
_TERMINAL = {"COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "STOPPED"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartBatchEvaluation returns a job in a non-terminal status that the service itself drives to
    a different, terminal status while the check only polls GetBatchEvaluation; a backend that
    completes synchronously or never advances the job fails.
    """
    client = ctx.client("bedrock-agentcore")
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("/sim2real/bedrock-agentcore-behav")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    name = ctx.unique_name("Sim2RealBatchEval")[:48].replace("-", "")

    created = client.start_batch_evaluation(
        batchEvaluationName=name,
        evaluators=[{"evaluatorId": "Builtin.Helpfulness"}],
        dataSourceConfig={
            "cloudWatchLogs": {
                "serviceNames": ["sim2real-test-service"],
                "logGroupNames": [log_group_name],
            }
        },
        tags={"sim2real": "true"},
    )
    batch_evaluation_id = created["batchEvaluationId"]
    initial_status = created["status"]
    ctx.on_cleanup(lambda: _delete_when_terminal(client, batch_evaluation_id))

    assert initial_status in _NON_TERMINAL, (
        f"expected StartBatchEvaluation to hand back a non-terminal status, got {initial_status!r}"
    )
    assert created["batchEvaluationId"] in created["batchEvaluationArn"], (
        f"expected batchEvaluationArn {created['batchEvaluationArn']!r} to embed "
        f"batchEvaluationId {created['batchEvaluationId']!r}"
    )

    final = _poll_until_terminal(client, batch_evaluation_id, timeout_s=180.0)
    final_status = final["status"]

    assert final_status in _TERMINAL, (
        f"batch evaluation {batch_evaluation_id} never reached a terminal status "
        f"(last observed status={final_status!r})"
    )
    assert final_status != initial_status, (
        "GetBatchEvaluation reported the exact same status the whole time -- the service "
        "must transition the job asynchronously on its own"
    )
    assert final["batchEvaluationId"] == batch_evaluation_id, (
        f"expected GetBatchEvaluation to echo batchEvaluationId {batch_evaluation_id!r}, "
        f"got {final['batchEvaluationId']!r}"
    )
    assert final.get("createdAt") is not None, (
        f"expected GetBatchEvaluation to report a createdAt timestamp, got {final.get('createdAt')!r}"
    )


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until_terminal(client, batch_evaluation_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_batch_evaluation(batchEvaluationId=batch_evaluation_id)
        if last["status"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"batch evaluation stuck in status {last['status'] if last else '?'} after {timeout_s}s")


def _delete_when_terminal(client, batch_evaluation_id, timeout_s=60.0, interval_s=2.0):
    """Delete the batch evaluation once it is terminal; raise if it never gets there."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            status = client.get_batch_evaluation(batchEvaluationId=batch_evaluation_id)["status"]
            last = status
            if status in _TERMINAL:
                client.delete_batch_evaluation(batchEvaluationId=batch_evaluation_id)
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(
        f"teardown: batch evaluation {batch_evaluation_id} not terminal after {timeout_s}s "
        f"(last status {last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

