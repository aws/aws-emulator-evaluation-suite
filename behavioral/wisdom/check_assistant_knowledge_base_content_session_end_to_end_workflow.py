"""assistant-knowledge-base-content-session-end-to-end-workflow."""
from __future__ import annotations

import time
import urllib.request
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assistant-knowledge-base-content-session-end-to-end-workflow"
GROUP = "e2e"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An assistant's knowledge base association reads back by Get and List, uploaded content reaches
    ACTIVE, a session reads back, GetRecommendations returns a list, and QueryAssistant finds the
    content by the marker in its excerpt or title.
    """
    wisdom = ctx.client("wisdom")
    resource_tags = {"team": "support", "stage": "sim2real-e2e"}

    # 1. assistant
    assistant = wisdom.create_assistant(
        name=ctx.unique_name("sim2real-e2e-asst-"), type="AGENT", tags=resource_tags
    )["assistant"]
    assistant_id = assistant["assistantId"]
    ctx.on_cleanup(lambda: wisdom.delete_assistant(assistantId=assistant_id))

    # 2. knowledge base + association, reflected by both single-get and list APIs
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-e2e-kb-"), knowledgeBaseType="CUSTOM", tags=resource_tags
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    assoc = wisdom.create_assistant_association(
        assistantId=assistant_id,
        associationType="KNOWLEDGE_BASE",
        association={"knowledgeBaseId": kb_id},
        tags=resource_tags,
    )["assistantAssociation"]
    assoc_id = assoc["assistantAssociationId"]
    ctx.on_cleanup(
        lambda: wisdom.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc_id)
    )

    fetched_assoc = wisdom.get_assistant_association(
        assistantId=assistant_id, assistantAssociationId=assoc_id
    )["assistantAssociation"]
    fetched_kb_id = fetched_assoc["associationData"]["knowledgeBaseAssociation"]["knowledgeBaseId"]
    assert fetched_kb_id == kb_id, (
        f"GetAssistantAssociation should reflect knowledge base {kb_id!r}, got {fetched_kb_id!r}"
    )

    listed_assoc = wisdom.list_assistant_associations(assistantId=assistant_id)["assistantAssociationSummaries"]
    listed_ids = [a["assistantAssociationId"] for a in listed_assoc]
    assert assoc_id in listed_ids, (
        f"expected association {assoc_id!r} in ListAssistantAssociations, got {listed_ids!r}"
    )

    # 3. content, uploaded via the presigned-URL flow into the associated knowledge base
    marker = uuid.uuid4().hex
    payload = f"end-to-end wisdom content marker={marker}".encode("utf-8")
    upload_id = _upload_bytes(ctx, wisdom, kb_id, "text/plain", payload)
    content = wisdom.create_content(
        knowledgeBaseId=kb_id, name=ctx.unique_name("sim2real-e2e-content-"), uploadId=upload_id, tags=resource_tags
    )["content"]
    content_id = content["contentId"]
    ctx.on_cleanup(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id))

    active_content = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert active_content["status"] == "ACTIVE", (
        f"content {content_id!r} should reach ACTIVE, got {active_content['status']!r}"
    )

    # 4. session on the assistant
    session = wisdom.create_session(
        assistantId=assistant_id, name=ctx.unique_name("sim2real-e2e-session-"), tags=resource_tags
    )["session"]
    session_id = session["sessionId"]
    got_session = wisdom.get_session(assistantId=assistant_id, sessionId=session_id)["session"]
    assert got_session["sessionId"] == session_id, (
        f"GetSession should reflect the created session {session_id!r}, got {got_session['sessionId']!r}"
    )

    # 5. the live session can be queried through both recommendation surfaces without error
    recs = wisdom.get_recommendations(assistantId=assistant_id, sessionId=session_id)
    assert isinstance(recs["recommendations"], list), (
        f"GetRecommendations on a live session should return a list, got {recs['recommendations']!r}"
    )

    # the marker and content id are generated at run time, so no canned response can satisfy this --
    # the query must actually surface the content this run uploaded, by id, through the search index
    matched = _poll_until(
        lambda: _find_by_content_id(_try_query(wisdom, assistant_id, "marker"), content_id),
        lambda m: m is not None,
        timeout_s=240.0,
        interval_s=5.0,
    )
    excerpt = (matched["document"].get("excerpt") or {}).get("text") or ""
    title = (matched["document"].get("title") or {}).get("text") or ""
    assert marker in excerpt or marker in title, (
        f"query_assistant('marker') matched content {content_id!r} by id, but neither its excerpt nor "
        f"its title carried the uploaded marker {marker!r}: excerpt={excerpt!r} title={title!r}"
    )


def _try_query(wisdom, assistant_id, query_text):
    try:
        return wisdom.query_assistant(assistantId=assistant_id, queryText=query_text)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None  # associated knowledge base's search index still warming up
        raise


def _find_by_content_id(query_response, content_id):
    if query_response is None:
        return None
    for result in query_response["results"]:
        if result["document"]["contentReference"].get("contentId") == content_id:
            return result
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _upload_bytes(ctx, wisdom, kb_id, content_type, data):
    up = wisdom.start_content_upload(knowledgeBaseId=kb_id, contentType=content_type)
    url, route = ctx.endpoint_route(up["url"])
    req = urllib.request.Request(
        url, data=data, method="PUT", headers=dict(up.get("headersToInclude", {}), **route)
    )
    with urllib.request.urlopen(req, timeout=30) as http_resp:
        if http_resp.status not in (200, 201, 204):
            raise AssertionError(f"content upload PUT failed with status {http_resp.status}")
    return up["uploadId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

