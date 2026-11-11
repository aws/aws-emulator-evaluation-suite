"""tag-resource-too-many-tags-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-too-many-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["oam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """Pushing a resource's tag count past the 50-tag ceiling is rejected; existing tags are untouched."""
    oam = ctx.client("oam")

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name)
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))

    fifty_tags = {f"k{i}": f"v{i}" for i in range(50)}
    oam.tag_resource(ResourceArn=sink_arn, Tags=fifty_tags)
    tags_after_fifty = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    assert len(tags_after_fifty) == 50, f"expected 50 tags after filling to the ceiling, got {len(tags_after_fifty)}"

    code, code_message = _error(lambda: oam.tag_resource(ResourceArn=sink_arn, Tags={"k50": "v50"}))
    assert code == "BadRequestException", f"got {code!r}"
    assert code_message == "The resultant tag set must not have more than 50 user tags.", f"got message {code_message!r}"

    # effect absent: still exactly the original 50 tags, no k50.
    tags_after_reject = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    assert len(tags_after_reject) == 50, f"expected the rejected call to leave 50 tags, got {len(tags_after_reject)}"
    assert "k50" not in tags_after_reject, f"k50 should not have been added by the rejected call, got {tags_after_reject!r}"

    # positive control: freeing a slot lets a new tag be added within the limit.
    oam.untag_resource(ResourceArn=sink_arn, TagKeys=["k0"])
    oam.tag_resource(ResourceArn=sink_arn, Tags={"k50": "v50"})
    final_tags = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    assert len(final_tags) == 50, f"expected 50 tags after freeing a slot and adding k50, got {len(final_tags)}"
    assert "k50" in final_tags, f"expected k50 present after freeing a slot, got {final_tags!r}"
    assert "k0" not in final_tags, f"expected k0 removed after untag_resource, got {final_tags!r}"


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
