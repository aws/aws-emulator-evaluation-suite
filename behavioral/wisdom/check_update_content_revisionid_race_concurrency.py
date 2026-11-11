"""update-content-revisionid-race-concurrency."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-content-revisionid-race-concurrency"
GROUP = "concurrency"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Of two concurrent UpdateContent calls with the same starting revisionId, exactly one succeeds
    and the other fails with PreconditionFailedException with an empty or "Request precondition failed" message;
    GetContent returns the winner's title.
    """
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-behav-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    upload = wisdom.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_upload(ctx, upload, b"race start body")
    content = wisdom.create_content(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-behav-content-"),
        title="Race Start",
        uploadId=upload["uploadId"],
        tags={"team": "support", "stage": "sim2real-behav"},
    )["content"]
    content_id = content["contentId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id)))

    active = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert active["status"] == "ACTIVE", f"expected ACTIVE, got {active['status']!r}"
    start_revision = active["revisionId"]

    def _racer(title):
        from botocore.exceptions import ClientError

        try:
            resp = wisdom.update_content(
                knowledgeBaseId=kb_id, contentId=content_id, revisionId=start_revision, title=title
            )
            return ("ok", resp["content"]["title"])
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_racer, ["Racer A Title", "Racer B Title"]))

    outcomes = [kind for kind, _ in results]
    assert outcomes.count("ok") == 1, f"expected exactly one winner, got {results}"
    assert outcomes.count("error") == 1, f"expected exactly one loser, got {results}"

    loser_code, loser_message = next(value for kind, value in results if kind == "error")
    assert loser_code == "PreconditionFailedException", (
        f"expected PreconditionFailedException for the loser, got {loser_code!r}"
    )
    # AWS refuses with "" when the loser reads the winner's revision, and with
    # "Request precondition failed" when both writes meet at the conditional write.
    assert loser_message in ("", "Request precondition failed"), loser_message

    winner_title = next(value for kind, value in results if kind == "ok")
    final = wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]
    assert final["title"] == winner_title, (
        f"expected persisted title {winner_title!r}, got {final['title']!r}"
    )


def _put_upload(ctx, upload, data):
    import urllib.request

    target_url, route_headers = ctx.endpoint_route(upload["url"])
    req = urllib.request.Request(
        target_url, data=data, method="PUT", headers={**upload.get("headersToInclude", {}), **route_headers}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status not in (200, 201, 204):
            raise AssertionError(f"content upload PUT failed with status {resp.status}")


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
