"""tag-resource-list-and-untag-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-and-untag-roundtrip"
GROUP = "data-plane"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on an Application resource."""
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-app-tags-")
    namespace = ctx.unique_name("sim2real-ns-tags-")

    created = appi.create_application(
        Name=name,
        Namespace=namespace,
        ApplicationSourceConfig={
            "ExternalUrlConfig": {"AccessUrl": "https://example.com/tags"}
        },
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: appi.delete_application(Arn=arn))

    before = appi.list_tags_for_resource(resourceArn=arn)
    assert before["tags"] == {}

    appi.tag_resource(resourceArn=arn, tags={"sim2real-key": "sim2real-value"})

    after_tag = appi.list_tags_for_resource(resourceArn=arn)
    assert after_tag["tags"] == {"sim2real-key": "sim2real-value"}

    # GetApplication's Tags field must reflect the same tag state.
    got = appi.get_application(Arn=arn)
    assert got.get("Tags", {}).get("sim2real-key") == "sim2real-value"

    appi.untag_resource(resourceArn=arn, tagKeys=["sim2real-key"])

    after_untag = appi.list_tags_for_resource(resourceArn=arn)
    assert after_untag["tags"] == {}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
