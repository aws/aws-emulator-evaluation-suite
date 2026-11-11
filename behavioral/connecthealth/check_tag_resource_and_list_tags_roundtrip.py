"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["connecthealth"]


def _create_domain(ch, name, **extra):
    deadline = time.monotonic() + 300.0
    while True:
        try:
            return ch.create_domain(name=name, **extra)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code not in ("ServiceQuotaExceededException", "ValidationException") or "maximum limit" not in msg:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a Domain resource."""
    ch = ctx.client("connecthealth")
    resp = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))
    domain_id = resp["domainId"]
    arn = resp["arn"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    initial = ch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert initial == {}, f"expected no tags on a freshly created domain, got {initial!r}"

    ch.tag_resource(resourceArn=arn, tags={"env": "sim2real-test"})
    tagged = ch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tagged == {"env": "sim2real-test"}, f"expected tag to round-trip, got {tagged!r}"

    ch.untag_resource(resourceArn=arn, tagKeys=["env"])
    after_untag = ch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after_untag == {}, f"expected untag_resource to remove the tag, got {after_untag!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
