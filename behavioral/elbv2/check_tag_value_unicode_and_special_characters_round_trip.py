"""tag-value-unicode-and-special-characters-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-and-special-characters-round-trip"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag keys/values with unicode letters and the allowed special characters
    round-trip byte-for-byte through AddTags/DescribeTags (no normalization,
    truncation, or mojibake introduced by the store)."""
    elbv2 = ctx.client("elbv2")

    name = _short_name(ctx, "sim2real-tg")
    tg = elbv2.create_target_group(Name=name, TargetType="lambda")["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    # Allowed tag pattern is ^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$ -- unicode letters,
    # unicode numbers, unicode separators (spaces) and the literal _.:/=+-@ set.
    unicode_key = "\u043a\u043b\u044e\u0447-\u65e5\u672c\u8a9e_1"  # "ключ-日本語_1"
    unicode_value = (
        "H\u00e9llo W\u00f6rld \u0422\u0435\u0441\u0442 \u65e5\u672c\u8a9e"
        " _.:/=+-@ 42"
    )  # "Héllo Wörld Тест 日本語 _.:/=+-@ 42"

    elbv2.add_tags(ResourceArns=[tg_arn], Tags=[{"Key": unicode_key, "Value": unicode_value}])

    described = elbv2.describe_tags(ResourceArns=[tg_arn])["TagDescriptions"][0]["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in described}

    assert unicode_key in tag_map, f"unicode tag key not found in {list(tag_map)}"
    assert tag_map[unicode_key] == unicode_value, (
        f"tag value corrupted: expected {unicode_value!r}, got {tag_map[unicode_key]!r}"
    )
    # Byte-level check too: guard against any lossy re-encoding round trip.
    assert tag_map[unicode_key].encode("utf-8") == unicode_value.encode("utf-8")


def _short_name(ctx, prefix: str) -> str:
    """A resource name that fits ELBv2's <=32 char naming limits."""
    name = ctx.unique_name(f"{prefix}-").replace("_", "-")
    return name[:32].rstrip("-")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
