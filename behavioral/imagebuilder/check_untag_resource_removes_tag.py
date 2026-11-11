"""untag-resource-removes-tag."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named key, leaving other tags intact."""
    ib = ctx.client("imagebuilder")
    component_arn = _create_component(ctx)

    key_a = ctx.unique_name("sim2real-ib-tagkey-a-")
    key_b = ctx.unique_name("sim2real-ib-tagkey-b-")
    ib.tag_resource(resourceArn=component_arn, tags={key_a: "a-value", key_b: "b-value"})

    ib.untag_resource(resourceArn=component_arn, tagKeys=[key_a])

    tags = ib.list_tags_for_resource(resourceArn=component_arn)["tags"]
    assert key_a not in tags, f"expected {key_a!r} removed by untag_resource, still present in {tags!r}"
    assert tags.get(key_b) == "b-value", f"expected {key_b!r}='b-value' retained, got {tags.get(key_b)!r}"


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
