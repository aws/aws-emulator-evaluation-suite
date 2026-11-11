"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a component is visible via ListTagsForResource."""
    ib = ctx.client("imagebuilder")
    component_arn = _create_component(ctx)

    tag_key = ctx.unique_name("sim2real-ib-tagkey-")
    before = ib.list_tags_for_resource(resourceArn=component_arn)["tags"]
    assert tag_key not in before, f"tag key {tag_key!r} present before TagResource was ever called: {before!r}"

    ib.tag_resource(resourceArn=component_arn, tags={tag_key: "tagged-value"})

    after = ib.list_tags_for_resource(resourceArn=component_arn)["tags"]
    assert after.get(tag_key) == "tagged-value", (
        f"expected tag {tag_key!r}='tagged-value' after TagResource, got {after.get(tag_key)!r}"
    )


def _create_component(ctx, version: str = "1.0.0", platform: str = "Linux") -> str:
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-comp-")
    doc = (
        f"name: {name}\n"
        "description: test component\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: UpdateOS\n"
        "        action: UpdateOS\n"
    )
    resp = ib.create_component(
        name=name, semanticVersion=version, platform=platform, data=doc, clientToken=str(uuid.uuid4())
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
