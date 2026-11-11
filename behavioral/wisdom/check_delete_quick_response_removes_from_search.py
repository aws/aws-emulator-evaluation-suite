"""delete-quick-response-removes-from-search."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-quick-response-removes-from-search"
GROUP = "data-plane"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteQuickResponse, SearchQuickResponses eventually stops returning the deleted
    quick response for a query that used to match it."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-behav-kb-"),
        knowledgeBaseType="QUICK_RESPONSES",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    unique_token = ctx.unique_name("zzdelbehavtoken").replace("-", "")
    qr = wisdom.create_quick_response(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-behav-qr-"),
        content={"content": f"marker {unique_token} present"},
        shortcutKey="delsrch1",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["quickResponse"]
    qr_id = qr["quickResponseId"]
    _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"],
        lambda q: q["status"] in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )

    def _search():
        try:
            return wisdom.search_quick_responses(
                knowledgeBaseId=kb_id,
                searchExpression={
                    "queries": [
                        {"name": "content", "values": [unique_token], "operator": "CONTAINS", "allowFuzziness": False}
                    ]
                },
            )["results"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return []  # search index still warming up right after KB/QR creation
            raise

    appear_started = time.monotonic()
    matches = _poll_until(_search, lambda results: len(results) >= 1, timeout_s=60.0)
    appear_latency_s = time.monotonic() - appear_started
    found_ids = [r["quickResponseId"] for r in matches]
    assert qr_id in found_ids, f"expected {qr_id} in search results, got {found_ids!r}"

    wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)

    def _no_longer_found():
        return qr_id not in [r["quickResponseId"] for r in _search()]

    # Absence must be held at least as long as it took the index to pick the item up in the
    # first place, not a guessed constant.
    absence_timeout_s = max(90.0, 3.0 * appear_latency_s)
    ok = _poll_bool(_no_longer_found, timeout_s=absence_timeout_s)
    assert ok, (
        f"deleted quick response {qr_id} was still returned by SearchQuickResponses after "
        f"{absence_timeout_s:.1f}s"
    )

    # Second independent observable: the direct read must also refuse the dead id.
    code, message = _poll_error(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id),
        timeout_s=30.0,
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetQuickResponse on deleted {qr_id}, got {code!r}"
    )
    assert message == "QuickResponse does not exist.", (
        f"expected the quick-response not-found message, got {message!r}"
    )


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_error(fn, *, timeout_s=30.0, interval_s=2.0):
    """Poll fn() until it raises; return that ClientError's (code, message), or fail on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"expected an error within {timeout_s}s, but the call kept succeeding (last={last!r})")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _poll_bool(probe, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
