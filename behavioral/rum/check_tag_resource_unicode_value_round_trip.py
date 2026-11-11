"""tag-resource-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value with unicode/emoji characters survives TagResource then ListTagsForResource unchanged."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    rum.create_app_monitor(Name=name, DomainList=["example.com"])
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    arn = _app_monitor_arn(ctx, name)

    # RUM's tag validation rejects characters outside letters/numbers/spaces plus
    # a fixed set of symbols (_.:/=+-@) — emoji and other non-letter symbols are
    # rejected, but non-ASCII *letters* (accented Latin, CJK, Greek) are permitted.
    # This still exercises unicode byte-for-byte round-tripping without tripping
    # that allow-list.
    unicode_value = "héllo-世界-Ω-café-日本語"
    rum.tag_resource(ResourceArn=arn, Tags={"sim2real-unicode-key": unicode_value})

    tags = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("sim2real-unicode-key") == unicode_value, (
        f"unicode tag value mutated in round-trip: {tags.get('sim2real-unicode-key')!r} "
        f"!= {unicode_value!r}"
    )


def _app_monitor_arn(ctx, name: str) -> str:
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    partition = identity["Arn"].split(":")[1]
    account = identity["Account"]
    return f"arn:{partition}:rum:{ctx.region}:{account}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
