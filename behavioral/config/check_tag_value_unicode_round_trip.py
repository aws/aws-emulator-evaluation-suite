"""tag-value-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode characters in tag keys/values survive TagResource and are
    returned byte-identical by ListTagsForResource."""
    cfg = ctx.client("config")
    query_name = ctx.unique_name("sim2real-tagquery-").replace("_", "-")

    query_arn = cfg.put_stored_query(
        StoredQuery={
            "QueryName": query_name,
            "Expression": "SELECT resourceId WHERE resourceType = 'AWS::S3::Bucket'",
        }
    )["QueryArn"]
    ctx.on_cleanup(lambda: cfg.delete_stored_query(QueryName=query_name))

    unicode_key = "\u30c6\u30b9\u30c8\u30ad\u30fc-abc"
    unicode_value = "\u00e9\u00e8\u00ea_\u4e2d\u6587.value:test"
    plain_key = "PlainKey"
    plain_value = ""  # tag values may be empty strings (min length 0)

    cfg.tag_resource(
        ResourceArn=query_arn,
        Tags=[
            {"Key": unicode_key, "Value": unicode_value},
            {"Key": plain_key, "Value": plain_value},
        ],
    )
    ctx.on_cleanup(
        lambda: cfg.untag_resource(
            ResourceArn=query_arn, TagKeys=[unicode_key, plain_key]
        )
    )

    tags_by_key = {
        t["Key"]: t["Value"]
        for t in cfg.list_tags_for_resource(ResourceArn=query_arn)["Tags"]
    }

    assert unicode_key in tags_by_key, f"unicode tag key missing: {tags_by_key.keys()}"
    assert tags_by_key[unicode_key] == unicode_value, (
        f"unicode tag value not byte-identical: {tags_by_key[unicode_key]!r} != {unicode_value!r}"
    )
    assert tags_by_key.get(plain_key) == plain_value, (
        f"empty-string tag value not preserved: {tags_by_key.get(plain_key)!r} != {plain_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
