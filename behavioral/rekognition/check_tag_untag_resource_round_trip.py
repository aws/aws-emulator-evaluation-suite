"""tag-untag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-untag-resource-round-trip"
GROUP = "state"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource; UntagResource removes only the requested key."""
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-tags-")
    collection_arn = rek.create_collection(CollectionId=collection_id)["CollectionArn"]
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))

    assert collection_arn.startswith(("arn:", "aws:")), collection_arn[:20]
    fixed_collection_arn = collection_arn if collection_arn.startswith("arn:") else "arn:" + collection_arn
    # empirical AWS quirk: CreateCollection's CollectionArn sometimes omits the "arn:" partition
    # prefix; TagResource requires the fully-qualified ARN form.
    rek.tag_resource(ResourceArn=fixed_collection_arn, Tags={"env": "sim2real", "owner": "behavioral"})
    tags = rek.list_tags_for_resource(ResourceArn=fixed_collection_arn)["Tags"]
    assert tags == {"env": "sim2real", "owner": "behavioral"}, f"expected both tags after TagResource, got {tags}"

    rek.untag_resource(ResourceArn=fixed_collection_arn, TagKeys=["owner"])
    tags_after = rek.list_tags_for_resource(ResourceArn=fixed_collection_arn)["Tags"]
    assert tags_after == {"env": "sim2real"}, f"expected only 'owner' removed after UntagResource, got {tags_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
