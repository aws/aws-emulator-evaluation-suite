"""recommendation-lifecycle."""
from __future__ import annotations

import datetime as _dt
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "recommendation-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartRecommendation produces a resource retrievable by GetRecommendation, and
    DeleteRecommendation removes it causing subsequent gets to ResourceNotFoundException."""
    client = ctx.client("bedrock-agentcore")
    logs = ctx.client("logs")
    name = _sanitize(ctx.unique_name("sim2realrec"))

    log_group_name = ctx.unique_name("/sim2real/bedrock-agentcore-rec")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    described = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]
    log_group_arn = described["arn"]

    now = _dt.datetime.now(_dt.timezone.utc)
    started = client.start_recommendation(
        name=name,
        type="SYSTEM_PROMPT_RECOMMENDATION",
        recommendationConfig={
            "systemPromptRecommendationConfig": {
                "systemPrompt": {"text": "You are a concise, helpful customer support agent."},
                "agentTraces": {
                    "cloudwatchLogs": {
                        "logGroupArns": [log_group_arn],
                        "serviceNames": ["sim2real-rec-service"],
                        "startTime": now - _dt.timedelta(days=7),
                        "endTime": now,
                    }
                },
                "evaluationConfig": {
                    "evaluators": [
                        {"evaluatorArn": "arn:aws:bedrock-agentcore:::evaluator/Builtin.Helpfulness"}
                    ]
                },
            }
        },
        tags={"sim2real": CHECK},
    )
    recommendation_id = started["recommendationId"]
    ctx.on_cleanup(lambda: _best_effort_delete(client, recommendation_id))

    got = client.get_recommendation(recommendationId=recommendation_id)
    assert got["recommendationId"] == recommendation_id, (
        f"expected recommendationId {recommendation_id!r}, got {got.get('recommendationId')!r}"
    )
    assert got["name"] == name, f"expected name {name!r}, got {got.get('name')!r}"
    assert got["type"] == "SYSTEM_PROMPT_RECOMMENDATION", (
        f"expected type SYSTEM_PROMPT_RECOMMENDATION, got {got.get('type')!r}"
    )
    assert got["status"] in ("PENDING", "IN_PROGRESS", "COMPLETED"), (
        f"expected a pre-terminal or already-COMPLETED status, got {got.get('status')!r}"
    )

    # No real agent telemetry exists in the (empty) log group, so the job is expected to
    # reach some terminal state (COMPLETED if it tolerates zero sessions, FAILED if it
    # requires at least one) -- either way, this confirms the PENDING/IN_PROGRESS ->
    # terminal state transition rather than the job hanging forever.
    final = _poll_until(
        lambda: client.get_recommendation(recommendationId=recommendation_id),
        lambda r: r["status"] in ("COMPLETED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final["status"] in ("COMPLETED", "FAILED"), (
        f"expected a terminal status, got {final.get('status')!r}"
    )
    assert final["recommendationId"] == recommendation_id, (
        f"expected recommendationId {recommendation_id!r}, got {final.get('recommendationId')!r}"
    )
    # Confirmed against real AWS rather than guessed: an empty log group deterministically
    # drives this to FAILED (no sessions found in the traces window), and the terminal
    # response -- COMPLETED or FAILED alike -- always carries a recommendationResult with a
    # systemPromptRecommendationResult, just populated differently: a recommendedSystemPrompt
    # on COMPLETED, an errorCode/errorMessage explaining the failure on FAILED. Asserting the
    # populated shape (not just its presence) means a target that flips the status word
    # without ever producing that payload cannot pass.
    result = final.get("recommendationResult")
    assert result, f"expected a non-empty recommendationResult on a terminal status, got {result!r}"
    prompt_result = result.get("systemPromptRecommendationResult")
    assert prompt_result, (
        f"expected systemPromptRecommendationResult for a SYSTEM_PROMPT_RECOMMENDATION, got keys {list(result)!r}"
    )
    if final["status"] == "COMPLETED":
        assert prompt_result.get("recommendedSystemPrompt"), (
            f"expected a non-empty recommendedSystemPrompt on COMPLETED, got {prompt_result!r}"
        )
    else:
        assert prompt_result.get("errorCode"), (
            f"expected an errorCode explaining the FAILED result, got {prompt_result!r}"
        )
        assert prompt_result.get("errorMessage"), (
            f"expected an errorMessage explaining the FAILED result, got {prompt_result!r}"
        )

    client.delete_recommendation(recommendationId=recommendation_id)

    code, message = _error(
        lambda: client.get_recommendation(recommendationId=recommendation_id),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Recommendation not found: recommendationId={recommendation_id}"
    assert message == expected, f"expected {expected!r}, got {message!r}"


def _sanitize(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "_-" else "" for c in name)
    if not cleaned[:1].isalpha():
        cleaned = "r" + cleaned
    return cleaned[:48]


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_delete(client, recommendation_id: str) -> None:
    try:
        client.delete_recommendation(recommendationId=recommendation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn, *, timeout_s=0.0, interval_s=2.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    succeeds once timeout_s has passed raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError("expected the call to be refused, but it succeeded")
        time.sleep(interval_s)


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
