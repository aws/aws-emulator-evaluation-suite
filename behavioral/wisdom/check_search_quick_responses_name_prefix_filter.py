"""search-quick-responses-name-prefix-filter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-quick-responses-name-prefix-filter"
GROUP = "data-plane"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchQuickResponses' queries narrow results by a CONTAINS_AND_PREFIX match on name: two
    quick responses sharing a name prefix are both returned by a query on that prefix, while a
    third with an unrelated name is excluded."""
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

    shared_prefix = ctx.unique_name("shpfx").replace("-", "")[:12]
    qr_ids = []
    for suffix, shortcut in (("alpha", "pfx1"), ("beta", "pfx2")):
        name = f"{shared_prefix}-{suffix}"[:40]
        qr = wisdom.create_quick_response(
            knowledgeBaseId=kb_id,
            name=name,
            content={"content": f"content for {name}"},
            shortcutKey=shortcut,
            tags={"team": "support", "stage": "sim2real-behav"},
        )["quickResponse"]
        qr_ids.append(qr["quickResponseId"])
        ctx.on_cleanup(
            lambda qid=qr["quickResponseId"]: _safe_delete(
                lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qid)
            )
        )
        final = _poll_until(
            lambda qid=qr["quickResponseId"]: wisdom.get_quick_response(
                knowledgeBaseId=kb_id, quickResponseId=qid
            )["quickResponse"],
            lambda q: q["status"] in ("CREATED", "CREATE_FAILED"),
            timeout_s=60.0,
        )
        assert final["status"] == "CREATED", f"quick response {name} did not reach CREATED: {final['status']!r}"

    unrelated_name = ctx.unique_name("sim2real-behav-unrelated-")[:40]
    unrelated = wisdom.create_quick_response(
        knowledgeBaseId=kb_id,
        name=unrelated_name,
        content={"content": "not part of the prefix group"},
        shortcutKey="pfx9",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["quickResponse"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=unrelated["quickResponseId"])
        )
    )
    unrelated_final = _poll_until(
        lambda: wisdom.get_quick_response(
            knowledgeBaseId=kb_id, quickResponseId=unrelated["quickResponseId"]
        )["quickResponse"],
        lambda q: q["status"] in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert unrelated_final["status"] == "CREATED", (
        f"unrelated quick response did not reach CREATED: {unrelated_final['status']!r}"
    )

    def _search_prefix():
        try:
            return wisdom.search_quick_responses(
                knowledgeBaseId=kb_id,
                searchExpression={
                    "queries": [{"name": "name", "values": [shared_prefix], "operator": "CONTAINS_AND_PREFIX"}]
                },
            )["results"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return []  # search index still warming up right after KB/QR creation
            raise

    found = _poll_until(_search_prefix, lambda results: len(results) >= 2, timeout_s=60.0)
    found_ids = {r["quickResponseId"] for r in found}
    assert set(qr_ids).issubset(found_ids), f"expected {qr_ids} in prefix-matched results, got {found_ids}"
    assert unrelated["quickResponseId"] not in found_ids, (
        f"unrelated quick response {unrelated['quickResponseId']} unexpectedly matched prefix {shared_prefix!r}"
    )


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
