"""tag-value-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag keys/values in multi-byte scripts (CJK, Cyrillic, Arabic) survive
    AddTags -> DescribeTags unchanged."""
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-elbv2-tg-")[:32].rstrip("-"),
        TargetType="lambda",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    # The ELBv2 tag pattern allows Unicode letters/separators/numbers but rejects emoji.
    tags = [
        {"Key": "环境", "Value": "生产环境"},
        {"Key": "команда", "Value": "инфраструктура"},
        {"Key": "الفريق", "Value": "شبكات"},
        {"Key": "note", "Value": "café naïve Zürich"},
    ]
    elbv2.add_tags(ResourceArns=[tg_arn], Tags=tags)

    fetched = elbv2.describe_tags(ResourceArns=[tg_arn])["TagDescriptions"][0]["Tags"]
    fetched_map = {t["Key"]: t["Value"] for t in fetched}
    expected_map = {t["Key"]: t["Value"] for t in tags}

    for key, value in expected_map.items():
        assert key in fetched_map, f"tag key {key!r} missing after round trip"
        assert fetched_map[key] == value, (
            f"tag value for {key!r} changed: sent {value!r}, got back {fetched_map[key]!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
