"""tag-resource-list-and-untag-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-and-untag-round-trip"
GROUP = "tagging"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes exactly the
    requested keys and leaves the rest untouched."""
    bda = ctx.client("bedrock-data-automation")
    project_arn = bda.create_data_automation_project(
        projectName=ctx.unique_name("sim2real-proj-"),
        standardOutputConfiguration={},
    )["projectArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_project(projectArn=project_arn))

    bda.tag_resource(
        resourceARN=project_arn,
        tags=[{"key": "Environment", "value": "sim2real-test"}, {"key": "Owner", "value": "behavioral"}],
    )

    tags_after_add = {t["key"]: t["value"] for t in bda.list_tags_for_resource(resourceARN=project_arn)["tags"]}
    assert tags_after_add["Environment"] == "sim2real-test", (
        f"expected Environment=sim2real-test after TagResource, got {tags_after_add.get('Environment')!r}"
    )
    assert tags_after_add["Owner"] == "behavioral", (
        f"expected Owner=behavioral after TagResource, got {tags_after_add.get('Owner')!r}"
    )

    bda.untag_resource(resourceARN=project_arn, tagKeys=["Environment"])

    tags_after_remove = {
        t["key"]: t["value"] for t in bda.list_tags_for_resource(resourceARN=project_arn)["tags"]
    }
    assert "Environment" not in tags_after_remove, (
        f"expected Environment removed by UntagResource, still present: {tags_after_remove}"
    )
    assert tags_after_remove["Owner"] == "behavioral", (
        f"expected Owner=behavioral to survive UntagResource(Environment), got {tags_after_remove.get('Owner')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
