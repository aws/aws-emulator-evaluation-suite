"""tag-resource-and-list-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-round-trip"
GROUP = "tagging"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags to a terminology resource that ListTagsForResource then reflects exactly."""
    translate = ctx.client("translate")
    name = ctx.unique_name("sim2real-term-")
    create_resp = translate.import_terminology(
        Name=name,
        MergeStrategy="OVERWRITE",
        TerminologyData={"File": b"en,es\nHello,Hola\n", "Format": "CSV"},
    )
    ctx.on_cleanup(lambda: translate.delete_terminology(Name=name))
    arn = create_resp["TerminologyProperties"]["Arn"]

    before = translate.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert before == [], f"expected a freshly-imported terminology to carry no tags, got {before!r}"

    translate.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": "project", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral-suite"}],
    )

    after = translate.list_tags_for_resource(ResourceArn=arn)["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in after}
    expected = {"project": "sim2real", "owner": "behavioral-suite"}
    assert tag_map == expected, f"expected ListTagsForResource to reflect {expected!r}, got {tag_map!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
