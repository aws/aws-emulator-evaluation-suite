"""tag-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["elasticache"]

# AWS's message, verbatim: the symbol list carries two backslashes and a stray closing quote.
_TAG_VALUE_CHARSET_MESSAGE = (
    "Tag values may only contain unicode letters, digits, whitespace, "
    'or one of these symbols: _ . : / = + \\\\ - @"'
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag values (emoji, CJK, Cyrillic, accented Latin) survive
    AddTagsToResource/ListTagsForResource byte-for-byte."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-tagcpg-")
    created = ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="unicode tag round-trip test group",
    )
    ctx.on_cleanup(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=name))
    arn = created["CacheParameterGroup"]["ARN"]

    unicode_tags = [
        {"Key": "cjk-tag", "Value": "\u4e16\u754c\u4f60\u597d"},
        {"Key": "cyrillic-tag", "Value": "\u041f\u0440\u0438\u0432\u0435\u0442-\u043c\u0438\u0440"},
        {"Key": "accented-tag", "Value": "cr\u00e8me br\u00fbl\u00e9e"},
    ]
    ec.add_tags_to_resource(ResourceName=arn, Tags=unicode_tags)

    listed = ec.list_tags_for_resource(ResourceName=arn)["TagList"]
    listed_by_key = {t["Key"]: t["Value"] for t in listed}
    for tag in unicode_tags:
        assert listed_by_key.get(tag["Key"]) == tag["Value"], (
            f"tag {tag['Key']!r} round-tripped as {listed_by_key.get(tag['Key'])!r}, "
            f"expected {tag['Value']!r}"
        )

    # Overly-permissive boundary: ElastiCache tag values are restricted to unicode letters,
    # digits, whitespace, and a small symbol set (_ . : / = + - @). An emoji is not a unicode
    # "letter" and must be rejected with InvalidParameterValue, not silently accepted/truncated.
    import botocore

    try:
        ec.add_tags_to_resource(
            ResourceName=arn, Tags=[{"Key": "emoji-tag", "Value": "party-\U0001F389-time"}]
        )
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] == "InvalidParameterValue", (
            f"expected InvalidParameterValue for emoji tag value, got {e.response['Error']['Code']!r}"
        )
        assert e.response["Error"].get("Message") == _TAG_VALUE_CHARSET_MESSAGE, (
            f"expected message {_TAG_VALUE_CHARSET_MESSAGE!r}, got {e.response['Error'].get('Message')!r}"
        )
    else:
        raise AssertionError("AddTagsToResource with an emoji tag value should have been rejected")

    after_reject = ec.list_tags_for_resource(ResourceName=arn)["TagList"]
    after_reject_by_key = {t["Key"]: t["Value"] for t in after_reject}
    assert "emoji-tag" not in after_reject_by_key, (
        f"rejected emoji tag was nonetheless applied: {after_reject_by_key.get('emoji-tag')!r}"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
