"""tag-resource-merges-and-untag-resource-is-idempotent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-merges-and-untag-resource-is-idempotent"
GROUP = 'tagging'
SERVICES = ['location']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A second TagResource call adds to the existing tag set rather than replacing
    it, and UntagResource on a key that was never set is a harmless no-op.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_TagResource.html
    """
    loc = ctx.client("location")
    collection = ctx.unique_name("sim2real-behav-location-collection-")
    arn = loc.create_geofence_collection(CollectionName=collection)["CollectionArn"]
    ctx.on_cleanup(_teardown(lambda: loc.delete_geofence_collection(CollectionName=collection),
                              "ResourceNotFoundException"))

    loc.tag_resource(ResourceArn=arn, Tags={"env": "sim2real"})
    assert loc.list_tags_for_resource(ResourceArn=arn)["Tags"] == {"env": "sim2real"}, (
        "expected only the first tag after one TagResource call"
    )

    loc.tag_resource(ResourceArn=arn, Tags={"owner": "probe"})
    merged = loc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert merged == {"env": "sim2real", "owner": "probe"}, (
        f"expected the second call to merge with the first, got {merged!r}"
    )

    loc.untag_resource(ResourceArn=arn, TagKeys=["never-set"])
    unchanged = loc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert unchanged == merged, (
        f"untagging a key that was never set changed the tag set: {unchanged!r} vs {merged!r}"
    )

    loc.untag_resource(ResourceArn=arn, TagKeys=["env"])
    final = loc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert final == {"owner": "probe"}, f"expected only 'owner' to remain, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
