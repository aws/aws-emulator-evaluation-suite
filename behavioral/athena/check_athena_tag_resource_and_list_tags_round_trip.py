"""athena-tag-resource-and-list-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-tag-resource-and-list-tags-round-trip"
GROUP = "data-plane"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource writes tags that ListTagsForResource reflects exactly; UntagResource removes them."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{name}"

    athena.tag_resource(ResourceARN=arn, Tags=[{"Key": "env", "Value": "behavioral-check"}, {"Key": "owner", "Value": "sim2real"}])

    tags = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags["env"] == "behavioral-check", f"expected env=behavioral-check, got {tags.get('env')!r}"
    assert tags["owner"] == "sim2real", f"expected owner=sim2real, got {tags.get('owner')!r}"

    athena.untag_resource(ResourceARN=arn, TagKeys=["env"])
    tags_after = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert "env" not in tags_after, f"expected 'env' removed by UntagResource, still present: {tags_after}"
    assert tags_after["owner"] == "sim2real", f"expected owner=sim2real to survive untag, got {tags_after.get('owner')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
