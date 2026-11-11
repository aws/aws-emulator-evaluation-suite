"""update-registry-description-persists-without-clobbering-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-registry-description-persists-without-clobbering-tags"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRegistry persists the new Description and leaves previously-set tags untouched."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    created = schemas.create_registry(RegistryName=registry, Description="original description")
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))
    arn = created["RegistryArn"]

    schemas.tag_resource(ResourceArn=arn, Tags={"Owner": "sim2real"})

    updated = schemas.update_registry(RegistryName=registry, Description="updated description")
    assert updated["Description"] == "updated description", (
        f"UpdateRegistry's own response should echo the new description, got {updated.get('Description')!r}"
    )

    described = schemas.describe_registry(RegistryName=registry)
    assert described["Description"] == "updated description", (
        f"expected DescribeRegistry to reflect the persisted description "
        f"'updated description', got {described.get('Description')!r}"
    )

    tags = schemas.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("Owner") == "sim2real", (
        f"expected UpdateRegistry to leave the Owner tag untouched at 'sim2real', got {tags.get('Owner')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
