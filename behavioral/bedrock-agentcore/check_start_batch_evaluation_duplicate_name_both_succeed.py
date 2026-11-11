"""start-batch-evaluation-duplicate-name-both-succeed."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-batch-evaluation-duplicate-name-both-succeed"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent StartBatchEvaluation calls reusing one batchEvaluationName (no clientToken)
    both succeed with distinct batchEvaluationIds that GetBatchEvaluation reads back under the
    same name: name uniqueness is not enforced at creation, so neither is refused."""
    agentcore = ctx.client("bedrock-agentcore")
    logs = ctx.client("logs")
    name = _batch_eval_name()

    log_group_name = ctx.unique_name("/sim2real/agentcore-be-")
    logs.create_log_group(
        logGroupName=log_group_name, tags={"sim2real": "start-batch-evaluation-duplicate-name-both-succeed"}
    )
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=log_group_name)))

    data_source_config = {
        "cloudWatchLogs": {
            "serviceNames": ["sim2real-test-service"],
            "logGroupNames": [log_group_name],
        }
    }
    evaluators = [{"evaluatorId": "Builtin.Helpfulness"}]

    def _start():
        try:
            resp = agentcore.start_batch_evaluation(
                batchEvaluationName=name,
                dataSourceConfig=data_source_config,
                evaluators=evaluators,
                tags={"sim2real": "start-batch-evaluation-duplicate-name-both-succeed"},
            )
            return ("ok", resp["batchEvaluationId"])
        except ClientError as e:
            return ("error", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_start) for _ in range(2)]
        outcomes = [f.result() for f in futures]

    successes = [o for o in outcomes if o[0] == "ok"]
    for _, batch_id in successes:
        ctx.on_cleanup(lambda b=batch_id: _safe_cleanup_batch_eval(agentcore, b))

    assert len(successes) == 2, f"expected both concurrent starts to succeed, got {outcomes}"
    ids = {batch_id for _, batch_id in successes}
    assert len(ids) == 2, f"expected two distinct batchEvaluationIds, got {ids}"

    # GetBatchEvaluation confirms both independently-created evaluations exist under the
    # same requested name.
    for batch_id in ids:
        got = agentcore.get_batch_evaluation(batchEvaluationId=batch_id)
        assert got["batchEvaluationName"] == name, (
            f"expected GetBatchEvaluation({batch_id}) to report name {name!r}, got {got.get('batchEvaluationName')!r}"
        )
        assert got["batchEvaluationId"] == batch_id, (
            f"expected GetBatchEvaluation to echo back id {batch_id}, got {got.get('batchEvaluationId')!r}"
        )


# ===== helpers =====
def _batch_eval_name() -> str:
    # BatchEvaluationName pattern: ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ (no hyphens allowed).
    return ("simrealbe" + uuid.uuid4().hex)[:40]


def _safe_cleanup_batch_eval(agentcore, batch_id: str) -> None:
    # Stop answers ConflictException on a job already terminal; delete answers it until the job
    # is terminal, so the delete retries that code alone.
    try:
        agentcore.stop_batch_evaluation(batchEvaluationId=batch_id)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            agentcore.delete_batch_evaluation(batchEvaluationId=batch_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
        time.sleep(2)
    _safe(lambda: agentcore.delete_batch_evaluation(batchEvaluationId=batch_id))


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

