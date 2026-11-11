"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes only the specified tag key, leaving the other tags on the application intact."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")

    resp = emrs.create_application(
        name=name,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real-keep": "yes", "sim2real-drop": "yes"},
    )
    app_id = resp["applicationId"]
    arn = resp["arn"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))

    before = emrs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert before.get("sim2real-keep") == "yes", f"expected sim2real-keep=yes, got {before!r}"
    assert before == {"sim2real-keep": "yes", "sim2real-drop": "yes"}, (
        f"expected exactly the two created tags, got {before!r}"
    )

    emrs.untag_resource(resourceArn=arn, tagKeys=["sim2real-drop"])

    after = emrs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after.get("sim2real-keep") == "yes", f"expected sim2real-keep=yes, got {after!r}"
    assert after == {"sim2real-keep": "yes"}, (
        f"expected only sim2real-keep to survive UntagResource, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
