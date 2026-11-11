"""tag-value-unicode-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-preserved"
GROUP = "representation"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag keys/values containing unicode persist unchanged through TagResource and DescribeSecret."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-tagunicode-")
    sm.create_secret(Name=name, SecretString="v1")
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    unicode_key = "城市-Team-Tag"
    unicode_value = "北京 café Zürich Москва"

    sm.tag_resource(
        SecretId=name,
        Tags=[{"Key": unicode_key, "Value": unicode_value}, {"Key": "Team", "Value": "platform"}],
    )

    desc = sm.describe_secret(SecretId=name)
    tags_by_key = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
    assert unicode_key in tags_by_key, f"unicode tag key not found among {list(tags_by_key)}"
    assert tags_by_key[unicode_key] == unicode_value, (
        f"unicode tag value mangled: expected {unicode_value!r}, got {tags_by_key[unicode_key]!r}"
    )
    assert tags_by_key.get("Team") == "platform", "sibling ASCII tag was affected by the unicode tag"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
