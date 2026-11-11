"""list-tags-for-resource-reflects-tag-and-untag."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-reflects-tag-and-untag"
GROUP = "state"
SERVICES = ["oam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """TagResource/UntagResource mutate the tag set observed via ListTagsForResource."""
    oam = ctx.client("oam")

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name)
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))

    before = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    assert before == {}, f"expected no tags on a freshly created sink, got {before!r}"

    oam.tag_resource(ResourceArn=sink_arn, Tags={"env": "sim2real", "team": "observability"})
    after_tag = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    expected_after_tag = {"env": "sim2real", "team": "observability"}
    assert after_tag == expected_after_tag, f"expected {expected_after_tag!r} after TagResource, got {after_tag!r}"

    oam.untag_resource(ResourceArn=sink_arn, TagKeys=["env"])
    after_untag = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    expected_after_untag = {"team": "observability"}
    assert after_untag == expected_after_untag, f"expected {expected_after_untag!r} after UntagResource, got {after_untag!r}"


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_sink_ignore_missing(oam, arn):
    try:
        oam.delete_sink(Identifier=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
