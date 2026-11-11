"""untag-resource-nonexistent-tag-key-noop."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-tag-key-noop"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource for a tag key that was never applied to the resource
    succeeds idempotently (no exception) and leaves the resource's existing
    tags completely untouched."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    s3tables.tag_resource(resourceArn=bucket_arn, tags={"sim2real-Keep": "yes"})

    # Removing a tag key that was never applied must not raise, and must not
    # touch the tag that IS present.
    s3tables.untag_resource(resourceArn=bucket_arn, tagKeys=["sim2real-Never-Applied"])

    tags = s3tables.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert tags == {"sim2real-Keep": "yes"}, f"unexpected tag state after no-op untag: {tags}"


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
