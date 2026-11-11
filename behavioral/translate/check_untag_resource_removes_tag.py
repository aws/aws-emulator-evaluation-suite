"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested tag key and leaves the remaining tags intact."""
    translate = ctx.client("translate")
    name = ctx.unique_name("sim2real-term-")
    create_resp = translate.import_terminology(
        Name=name,
        MergeStrategy="OVERWRITE",
        TerminologyData={"File": b"en,es\nHello,Hola\n", "Format": "CSV"},
    )
    ctx.on_cleanup(lambda: translate.delete_terminology(Name=name))
    arn = create_resp["TerminologyProperties"]["Arn"]

    translate.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": "keep", "Value": "yes"}, {"Key": "remove", "Value": "please"}],
    )
    tag_map = {t["Key"]: t["Value"] for t in translate.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tag_map == {"keep": "yes", "remove": "please"}, (
        f"expected both tags present before untag, got {tag_map}"
    )

    translate.untag_resource(ResourceArn=arn, TagKeys=["remove"])

    after = {t["Key"]: t["Value"] for t in translate.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert after == {"keep": "yes"}, (
        f"expected only 'keep' tag to remain after untagging 'remove', got {after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
