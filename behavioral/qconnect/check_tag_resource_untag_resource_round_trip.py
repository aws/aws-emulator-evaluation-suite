"""tag-resource-untag-resource-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-untag-resource-round-trip"
GROUP = "tagging"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource/ListTagsForResource round-trip on a knowledge base ARN."""
    qc = ctx.client("qconnect")
    name = ctx.unique_name("sim2real-qc-kb-")
    kb = qc.create_knowledge_base(name=name, knowledgeBaseType="CUSTOM")["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    kb_arn = kb["knowledgeBaseArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"knowledge base did not reach ACTIVE, got {status}"

    before = qc.list_tags_for_resource(resourceArn=kb_arn).get("tags", {})
    assert before == {}, f"expected no tags on a freshly created resource, found {before}"

    tags_to_add = {"sim2real-env": "test", "sim2real-owner": "behavioral-suite"}
    qc.tag_resource(resourceArn=kb_arn, tags=tags_to_add)
    after_tag = qc.list_tags_for_resource(resourceArn=kb_arn)["tags"]
    assert after_tag == tags_to_add, f"expected {tags_to_add}, got {after_tag}"

    qc.untag_resource(resourceArn=kb_arn, tagKeys=["sim2real-env"])
    after_untag = qc.list_tags_for_resource(resourceArn=kb_arn)["tags"]
    assert after_untag == {"sim2real-owner": "behavioral-suite"}, f"unexpected tags after untag: {after_untag}"


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
