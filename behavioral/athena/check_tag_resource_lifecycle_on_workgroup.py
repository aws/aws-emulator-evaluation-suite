"""tag-resource-lifecycle-on-workgroup."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle-on-workgroup"
GROUP = "data-plane-depth"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip a tag on a workgroup's
    ARN exactly."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{name}"
    tags_before = athena.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert tags_before == [], f"freshly created workgroup must have no tags, got {tags_before}"

    athena.tag_resource(ResourceARN=arn, Tags=[{"Key": "Environment", "Value": "behavioral-check"}])
    tags = athena.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert {"Key": "Environment", "Value": "behavioral-check"} in tags, (
        f"expected tag Environment=behavioral-check in {tags}"
    )

    athena.untag_resource(ResourceARN=arn, TagKeys=["Environment"])
    tags_after = athena.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert tags_after == [], f"tag must be gone after UntagResource, got {tags_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
