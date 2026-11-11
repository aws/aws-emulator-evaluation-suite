"""update-deleted-evaluator-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-deleted-evaluator-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]

_TAGS = {"sim2real": "update-deleted-evaluator-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateEvaluator on a deleted evaluator is refused with ResourceNotFoundException "Evaluator does not exist",
    while a live evaluator's update settles ACTIVE with the new description."""
    bac = ctx.client("bedrock-agentcore-control")

    def _config():
        return {
            "llmAsAJudge": {
                "instructions": (
                    "Rate the helpfulness of the assistant's response on a 1-5 scale. "
                    "Assistant response: {assistant_turn}"
                ),
                "ratingScale": {
                    "numerical": [
                        {"label": "poor", "value": 1.0, "definition": "Not helpful at all"},
                        {"label": "excellent", "value": 5.0, "definition": "Extremely helpful"},
                    ]
                },
                "modelConfig": {
                    "bedrockEvaluatorModelConfig": {"modelId": "amazon.nova-lite-v1:0"}
                },
            }
        }

    name1 = _alnum(ctx, "s2rEval", 48)
    created = bac.create_evaluator(
        evaluatorName=name1, evaluatorConfig=_config(), level="TRACE", tags=_TAGS
    )
    evaluator_id = created["evaluatorId"]
    ctx.on_cleanup(lambda: _safe(lambda: bac.delete_evaluator(evaluatorId=evaluator_id)))

    bac.delete_evaluator(evaluatorId=evaluator_id)
    _poll_until_gone(bac, evaluator_id)

    code, message = _error(
        lambda: bac.update_evaluator(evaluatorId=evaluator_id, description="should not apply")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = "Evaluator does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: updating a live evaluator works.
    name2 = _alnum(ctx, "s2rEval2", 48)
    created2 = bac.create_evaluator(
        evaluatorName=name2, evaluatorConfig=_config(), level="TRACE", tags=_TAGS
    )
    evaluator_id2 = created2["evaluatorId"]
    ctx.on_cleanup(lambda: _safe(lambda: bac.delete_evaluator(evaluatorId=evaluator_id2)))

    updated = bac.update_evaluator(evaluatorId=evaluator_id2, description="updated description")
    assert updated["evaluatorId"] == evaluator_id2

    settled = _poll_until_settled(bac, evaluator_id2)
    assert settled["status"] == "ACTIVE", f"expected ACTIVE, got {settled['status']!r}"
    assert settled["description"] == "updated description", (
        f"expected description to be updated, got {settled['description']!r}"
    )


def _alnum(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9_]", "", raw)
    return name[:maxlen]


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until_settled(bac, evaluator_id: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = bac.get_evaluator(evaluatorId=evaluator_id)
        if last["status"] != "UPDATING":
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"evaluator {evaluator_id} did not settle within {timeout_s}s; last={last!r}"
    )


def _poll_until_gone(bac, evaluator_id: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            bac.get_evaluator(evaluatorId=evaluator_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"evaluator {evaluator_id} was not fully removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
