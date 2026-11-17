"""get-tags-exact-map-through-tag-untag-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-tags-exact-map-through-tag-untag-round-trip"
GROUP = "tags"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTags on a database or registry ARN returns exactly the map TagResource/UntagResource
    last left it with, never a superset or subset, and tagging one leaves the other's map
    exactly as it was.
    """
    glue = ctx.client("glue")

    db_name = ctx.unique_name("sim2real-behav-db-")
    db_tags = {"billing-unit": "warehouse-eng", "retention": "short"}
    glue.create_database(DatabaseInput={"Name": db_name}, Tags=db_tags)
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    db_arn = f"arn:aws:glue:{ctx.region}:{ctx.account}:database/{db_name}"

    registry_name = ctx.unique_name("sim2real-behav-registry-")
    registry_tags = {"billing-unit": "contracts-eng", "retention": "long"}
    glue.create_registry(RegistryName=registry_name, Tags=registry_tags)
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry_name}))
    registry_arn = f"arn:aws:glue:{ctx.region}:{ctx.account}:registry/{registry_name}"

    db_read = glue.get_tags(ResourceArn=db_arn)["Tags"]
    assert db_read == db_tags, f"database tags after create were {db_read!r}, expected {db_tags!r}"
    registry_read = glue.get_tags(ResourceArn=registry_arn)["Tags"]
    assert registry_read == registry_tags, (
        f"registry tags after create were {registry_read!r}, expected {registry_tags!r}"
    )

    glue.tag_resource(ResourceArn=registry_arn, TagsToAdd={"owner": "data-platform-team"})
    registry_tags = {**registry_tags, "owner": "data-platform-team"}
    registry_read = glue.get_tags(ResourceArn=registry_arn)["Tags"]
    assert registry_read == registry_tags, (
        f"registry tags after tag_resource were {registry_read!r}, expected {registry_tags!r}"
    )
    db_read = glue.get_tags(ResourceArn=db_arn)["Tags"]
    assert db_read == db_tags, (
        f"tagging the registry changed the database's tags to {db_read!r}, expected {db_tags!r}"
    )

    glue.untag_resource(ResourceArn=registry_arn, TagsToRemove=["retention"])
    del registry_tags["retention"]
    registry_read = glue.get_tags(ResourceArn=registry_arn)["Tags"]
    assert registry_read == registry_tags, (
        f"registry tags after untag_resource were {registry_read!r}, expected {registry_tags!r}"
    )
    db_read = glue.get_tags(ResourceArn=db_arn)["Tags"]
    assert db_read == db_tags, (
        f"untagging the registry changed the database's tags to {db_read!r}, expected {db_tags!r}"
    )

    glue.tag_resource(ResourceArn=db_arn, TagsToAdd={"owner": "warehouse-team"})
    db_tags = {**db_tags, "owner": "warehouse-team"}
    db_read = glue.get_tags(ResourceArn=db_arn)["Tags"]
    assert db_read == db_tags, (
        f"database tags after tag_resource were {db_read!r}, expected {db_tags!r}"
    )
    registry_read = glue.get_tags(ResourceArn=registry_arn)["Tags"]
    assert registry_read == registry_tags, (
        f"tagging the database changed the registry's tags to {registry_read!r}, expected {registry_tags!r}"
    )

    glue.untag_resource(ResourceArn=db_arn, TagsToRemove=["retention"])
    del db_tags["retention"]
    db_read = glue.get_tags(ResourceArn=db_arn)["Tags"]
    assert db_read == db_tags, (
        f"database tags after untag_resource were {db_read!r}, expected {db_tags!r}"
    )
    registry_read = glue.get_tags(ResourceArn=registry_arn)["Tags"]
    assert registry_read == registry_tags, (
        f"untagging the database changed the registry's tags to {registry_read!r}, expected {registry_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
