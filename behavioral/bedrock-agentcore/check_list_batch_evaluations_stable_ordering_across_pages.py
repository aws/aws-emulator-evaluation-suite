"""list-batch-evaluations-stable-ordering-across-pages."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-batch-evaluations-stable-ordering-across-pages"
GROUP = "ordering"
SERVICES = ["bedrock-agentcore"]

_EVALUATORS = [{"evaluatorId": "Builtin.Helpfulness"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBatchEvaluations preserves a stable relative ordering of previously-created
    evaluations across a paginated traversal, even when a new evaluation is started
    concurrently with that traversal (no duplicate, dropped, or reordered entries)."""
    agentcore = ctx.client("bedrock-agentcore")
    logs = ctx.client("logs")
    prefix = ("simrealbeord" + uuid.uuid4().hex)[:20]

    log_group_name = ctx.unique_name("/sim2real/agentcore-beord-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    data_source_config = {
        "cloudWatchLogs": {
            "serviceNames": ["sim2real-test-service"],
            "logGroupNames": [log_group_name],
        }
    }

    created_ids = []
    for i in range(4):
        name = f"{prefix}{i}"
        resp = agentcore.start_batch_evaluation(
            batchEvaluationName=name,
            dataSourceConfig=data_source_config,
            evaluators=_EVALUATORS,
            tags={"sim2real-check": CHECK},
        )
        bid = resp["batchEvaluationId"]
        created_ids.append(bid)
        ctx.on_cleanup(lambda b=bid: _safe_cleanup(agentcore, b))
        time.sleep(1.2)

    id_to_position: dict[str, int] = {}
    ordered_seen: list[str] = []
    next_token = None
    started_extra = False
    page_count = 0
    max_pages = 300

    while True:
        kwargs = {"maxResults": 5}
        if next_token:
            kwargs["nextToken"] = next_token
        page = agentcore.list_batch_evaluations(**kwargs)
        for item in page["batchEvaluations"]:
            bid = item["batchEvaluationId"]
            assert bid not in id_to_position, f"duplicate id {bid} seen across pages"
            id_to_position[bid] = len(ordered_seen)
            ordered_seen.append(bid)
        next_token = page.get("nextToken")
        page_count += 1

        if not started_extra and page_count == 2:
            extra_name = f"{prefix}extra"
            extra_resp = agentcore.start_batch_evaluation(
                batchEvaluationName=extra_name,
                dataSourceConfig=data_source_config,
                evaluators=_EVALUATORS,
                tags={"sim2real-check": CHECK},
            )
            extra_id = extra_resp["batchEvaluationId"]
            created_ids.append(extra_id)
            ctx.on_cleanup(lambda b=extra_id: _safe_cleanup(agentcore, b))
            started_extra = True

        all_found = started_extra and all(cid in id_to_position for cid in created_ids)
        if all_found or not next_token or page_count >= max_pages:
            break

    missing = [cid for cid in created_ids if cid not in id_to_position]
    if missing:
        raise AssertionError(
            f"could not locate {len(missing)}/{len(created_ids)} test-created evaluations "
            f"within a bounded {max_pages}-page scan; this account likely has enough "
            "pre-existing evaluation history to make an exhaustive scan impractical here"
        )

    positions = [id_to_position[cid] for cid in created_ids]
    assert positions == sorted(positions) or positions == sorted(positions, reverse=True), (
        f"pagination did not preserve a stable relative order for our items: {positions}"
    )


# ===== helpers =====
def _safe_cleanup(agentcore, batch_id: str) -> None:
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
