"""quick-response-shortcut-key-race-concurrency."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "quick-response-shortcut-key-race-concurrency"
GROUP = "concurrency"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateQuickResponse calls in the same knowledge base racing to claim the
    same shortcutKey must resolve to exactly one winner; the loser gets ConflictException and no
    orphan quick response with that shortcutKey is left behind."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-behav-kb-"), knowledgeBaseType="QUICK_RESPONSES"
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    shared_key = "racedkey"

    def _racer(name):
        from botocore.exceptions import ClientError

        try:
            resp = wisdom.create_quick_response(
                knowledgeBaseId=kb_id, name=name, content={"content": name}, shortcutKey=shared_key
            )
            return ("ok", resp["quickResponse"]["quickResponseId"])
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message")))

    name_a = ctx.unique_name("sim2real-behav-race-a-")
    name_b = ctx.unique_name("sim2real-behav-race-b-")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_racer, [name_a, name_b]))

    outcomes = [kind for kind, _ in results]
    assert outcomes.count("ok") == 1, f"expected exactly one winner, got {results}"
    assert outcomes.count("error") == 1, f"expected exactly one loser, got {results}"

    loser_error = next(value for kind, value in results if kind == "error")
    expected_error = (
        "ConflictException",
        "The value for shortcut key is already in use. Please update and try again.",
    )
    assert loser_error == expected_error, f"expected loser error {expected_error!r}, got {loser_error!r}"

    winner_id = next(value for kind, value in results if kind == "ok")
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=winner_id)))

    listed = wisdom.list_quick_responses(knowledgeBaseId=kb_id)["quickResponseSummaries"]
    matching_key = [q for q in listed if q["quickResponseId"] == winner_id]
    assert len(matching_key) == 1, f"expected winner {winner_id} to appear once in listing, got {listed}"
    assert len(listed) == 1, f"expected exactly one quick response after the race, got {listed}"


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
