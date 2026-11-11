"""tag-resource-list-and-untag-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-and-untag-roundtrip"
GROUP = 'tagging'
SERVICES = ['athena']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a WorkGroup ARN."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(Name=name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    account = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:athena:{ctx.region}:{account}:workgroup/{name}"

    athena.tag_resource(
        ResourceARN=arn, Tags=[{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "data"}]
    )

    tags = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags.get("env") == "test", f"expected env=test, got {tags.get('env')!r}"
    assert tags.get("team") == "data", f"expected team=data, got {tags.get('team')!r}"

    athena.untag_resource(ResourceARN=arn, TagKeys=["env"])

    tags_after = {
        t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]
    }
    assert "env" not in tags_after, "untagged key should be gone"
    assert tags_after.get("team") == "data", "untouched key should remain"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
