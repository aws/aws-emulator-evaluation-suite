"""tag-resource-list-and-untag-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-and-untag-round-trip"
GROUP = "tagging"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a registry's ARN."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    created = schemas.create_registry(RegistryName=registry)
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))
    arn = created["RegistryArn"]

    schemas.tag_resource(ResourceArn=arn, Tags={"Environment": "test", "Team": "sim2real"})
    tags = schemas.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("Environment") == "test", f"expected Environment=test, got {tags.get('Environment')!r}"
    assert tags.get("Team") == "sim2real", f"expected Team=sim2real, got {tags.get('Team')!r}"

    schemas.untag_resource(ResourceArn=arn, TagKeys=["Environment"])
    tags_after = schemas.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "Environment" not in tags_after, f"expected Environment removed, still present: {tags_after}"
    assert tags_after.get("Team") == "sim2real", f"expected Team=sim2real to survive untag, got {tags_after.get('Team')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
