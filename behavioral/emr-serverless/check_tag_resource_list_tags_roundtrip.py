"""tag-resource-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on an application is reflected by a subsequent ListTagsForResource call."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")

    resp = emrs.create_application(
        name=name,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
    )
    app_id = resp["applicationId"]
    arn = resp["arn"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))

    before = emrs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-marker" not in before, (
        f"expected no sim2real-marker tag on a freshly created application, got tags={before}"
    )

    emrs.tag_resource(resourceArn=arn, tags={"sim2real-marker": "roundtrip"})

    after = emrs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after.get("sim2real-marker") == "roundtrip", (
        f"expected sim2real-marker=roundtrip after TagResource, got tags={after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
