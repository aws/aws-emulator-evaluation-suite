"""target-group-tag-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "target-group-tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing multi-byte unicode characters set via AddTags is returned
    unchanged by DescribeTags — no NFC/NFD normalization, escaping, or mangling."""
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-tg-")
    arn = elbv2.create_target_group(Name=name, TargetType="lambda")["TargetGroups"][0][
        "TargetGroupArn"
    ]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=arn))

    # ELB tag values may contain letters, spaces, and numbers representable in UTF-8, plus
    # + - = . _ : / @ (per the ELB tag-restrictions docs). Multi-byte *letters* (accented
    # Latin, CJK, Greek) are allowed; symbol-category codepoints like emoji are not, so this
    # deliberately sticks to letters to stay within the documented, empirically-accepted set.
    unicode_value = "héllo-世界-Ω-Ā"
    elbv2.add_tags(ResourceArns=[arn], Tags=[{"Key": "sim2real-unicode", "Value": unicode_value}])

    tag_descriptions = elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"]
    assert len(tag_descriptions) == 1, (
        f"expected exactly one TagDescriptions entry for {arn}, got {len(tag_descriptions)}"
    )
    tags = {t["Key"]: t["Value"] for t in tag_descriptions[0]["Tags"]}
    assert tags["sim2real-unicode"] == unicode_value, (
        f"tag value round-tripped as {tags.get('sim2real-unicode')!r}, expected {unicode_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
