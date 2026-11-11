"""update-quick-response-concurrent-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-quick-response-concurrent-race"
GROUP = "concurrency"
SERVICES = ["wisdom"]

_PRECONDITION_MESSAGE = "Request precondition failed"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateQuickResponse calls changing one quick response's description: a loser
    is refused only with PreconditionFailedException and its exact message, and the persisted
    description is a successful writer's."""
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

    qr = wisdom.create_quick_response(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-behav-qr-"),
        content={"content": "Race base content"},
        shortcutKey="racekey",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["quickResponse"]
    qr_id = qr["quickResponseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)))
    created = _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"],
        lambda q: q["status"] in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert created["status"] == "CREATED", f"quick response failed to create: {created!r}"

    def _racer(description):
        from botocore.exceptions import ClientError

        try:
            resp = wisdom.update_quick_response(
                knowledgeBaseId=kb_id, quickResponseId=qr_id, description=description
            )
            return ("ok", resp["quickResponse"]["description"])
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_racer, ["Racer A description", "Racer B description"]))

    written = [value for kind, value in results if kind == "ok"]
    refused = [value for kind, value in results if kind == "error"]
    assert written, f"expected at least one UpdateQuickResponse racer to succeed, got {results!r}"
    # An overlapping writer may be refused; serialized writers both succeed.
    assert all(error == ("PreconditionFailedException", _PRECONDITION_MESSAGE) for error in refused), (
        f"a refused racer must get PreconditionFailedException with its exact message, got {refused!r}"
    )

    final = _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"],
        lambda q: q["status"] == "CREATED",
        timeout_s=60.0,
    )
    assert final["description"] in written, f"expected final description in {written!r}, got {final['description']!r}"


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
