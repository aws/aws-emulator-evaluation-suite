"""evaluator-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "evaluator-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]

_TAGS = {"sim2real": "evaluator-lifecycle-transitions"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Evaluator create->CREATING->ACTIVE, UpdateEvaluator is accepted while
    ACTIVE and returns to ACTIVE, and DeleteEvaluator leaves no residual
    state (GetEvaluator returns ResourceNotFoundException)."""
    bac = ctx.client("bedrock-agentcore-control")
    name = _safe_name(ctx, "sim2realev")

    create_resp = bac.create_evaluator(
        evaluatorName=name,
        evaluatorConfig={
            "llmAsAJudge": {
                "instructions": "Rate how helpful the agent response is on a 0-1 scale.\n\nContext: {context}",
                "modelConfig": {
                    "bedrockEvaluatorModelConfig": {
                        "modelId": "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
                    }
                },
                "ratingScale": {
                    "numerical": [
                        {"label": "poor", "value": 0.0, "definition": "Not helpful"},
                        {"label": "good", "value": 1.0, "definition": "Helpful"},
                    ]
                },
            }
        },
        level="TRACE",
        tags=_TAGS,
    )
    evaluator_id = create_resp["evaluatorId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_evaluator(evaluatorId=evaluator_id)))

    ev = _poll_until(
        lambda: bac.get_evaluator(evaluatorId=evaluator_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )
    assert ev["status"] == "ACTIVE", f"unexpected terminal status {ev['status']!r}"

    bac.update_evaluator(evaluatorId=evaluator_id, description="sim2real-updated")
    ev2 = _poll_until(
        lambda: bac.get_evaluator(evaluatorId=evaluator_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
    )
    assert ev2["status"] == "ACTIVE", f"unexpected terminal status {ev2['status']!r}"
    assert ev2["description"] == "sim2real-updated", (
        f"UpdateEvaluator returned ACTIVE but the independent read shows "
        f"description={ev2['description']!r}, expected 'sim2real-updated'"
    )

    bac.delete_evaluator(evaluatorId=evaluator_id)
    code, message = _wait_rejected(
        lambda: bac.get_evaluator(evaluatorId=evaluator_id), timeout_s=90.0
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Evaluator does not exist", (
        f"expected message 'Evaluator does not exist', got {message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _wait_rejected(fn, *, timeout_s, interval_s=3.0):
    """Retry ``fn`` until it is rejected and return its (code, message); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _error(fn)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _safe_delete(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
