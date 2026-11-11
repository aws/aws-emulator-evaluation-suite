"""representation-tag-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "representation-tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value of accented Latin and CJK letters persists unchanged through TagResource ->
    ListTagsForResource (RUM tag keys allow only ASCII, so the Unicode payload sits in the value)."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-unitag-")
    rum.create_app_monitor(Name=name, Domain="localhost")
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    arn = _app_monitor_arn(ctx, name)

    unicode_value = "h\u00e9llo-w\u00f6rld-\u65e5\u672c\u8a9e"
    rum.tag_resource(ResourceArn=arn, Tags={"UnicodeValueTag": unicode_value})

    tags = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags["UnicodeValueTag"] == unicode_value, (
        f"unicode tag value mutated in round-trip: {tags['UnicodeValueTag']!r} "
        f"!= {unicode_value!r}"
    )


def _app_monitor_arn(ctx, name: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:rum:{ctx.region}:{account_id}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
