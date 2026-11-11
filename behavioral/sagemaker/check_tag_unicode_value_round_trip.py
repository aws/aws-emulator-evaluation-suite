"""tag-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value with multi-byte unicode letters reads back byte-identical from ListTags beside an
    ASCII tag, and a value with an emoji (outside the TagValue pattern) is refused with
    ValidationException and its exact message and is not stored.
    """
    sm = ctx.client("sagemaker")
    group_name = ctx.unique_name("sim2real-tagunicode-")
    create_resp = sm.create_model_package_group(ModelPackageGroupName=group_name)
    group_arn = create_resp["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    unicode_value = "héllo 世界 Ω café naïve ключ"
    tag_key = "sim2real-unicode-tag"
    sm.add_tags(ResourceArn=group_arn, Tags=[{"Key": tag_key, "Value": unicode_value}])

    tags = sm.list_tags(ResourceArn=group_arn)["Tags"]
    matching = [t for t in tags if t["Key"] == tag_key]
    assert len(matching) == 1, f"expected exactly one tag {tag_key!r}, got {matching}"
    assert matching[0]["Value"] == unicode_value, (
        f"unicode tag value not byte-identical: wrote {unicode_value!r}, "
        f"read back {matching[0]['Value']!r}"
    )

    # Positive control: a plain-ASCII tag on the same resource must also round-trip,
    # proving the mismatch (if any) above was specific to the unicode payload.
    ascii_key = "sim2real-ascii-tag"
    sm.add_tags(ResourceArn=group_arn, Tags=[{"Key": ascii_key, "Value": "plain-ascii-value"}])
    tags2 = sm.list_tags(ResourceArn=group_arn)["Tags"]
    ascii_matching = [t for t in tags2 if t["Key"] == ascii_key]
    assert len(ascii_matching) == 1
    assert ascii_matching[0]["Value"] == "plain-ascii-value"

    # Negative: a symbol character outside \p{L}\p{Z}\p{N} plus the fixed
    # punctuation set (an emoji) is a pattern violation, not a representable value.
    from botocore.exceptions import ClientError

    invalid_key = "sim2real-invalid-unicode-tag"
    try:
        sm.add_tags(ResourceArn=group_arn, Tags=[{"Key": invalid_key, "Value": "🚀"}])
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ValidationException", f"expected ValidationException, got {code}"
        expected_message = (
            "1 validation error detected: Value '\U0001F680' at 'tags.1.member.value' failed to "
            "satisfy constraint: Member must satisfy regular expression pattern: "
            "([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)"
        )
        message = e.response["Error"].get("Message")
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        raise AssertionError("AddTags accepted a tag value outside TagValue's pattern")

    tags3 = sm.list_tags(ResourceArn=group_arn)["Tags"]
    assert not any(t["Key"] == invalid_key for t in tags3), (
        f"rejected tag {invalid_key} was nonetheless visible via ListTags: {tags3}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
