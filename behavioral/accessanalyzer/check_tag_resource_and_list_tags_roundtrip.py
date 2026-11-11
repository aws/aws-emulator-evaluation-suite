"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "state-machine"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """TagResource/UntagResource actually mutate the resource's tag set, as observed via
    both ListTagsForResource and GetAnalyzer (not merely accepted and discarded)."""
    aa = ctx.client("accessanalyzer")
    name = ctx.unique_name("sim2real-aa-tags-")
    arn = aa.create_analyzer(analyzerName=name, type="ACCOUNT")["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=name))

    aa.tag_resource(resourceArn=arn, tags={"sim2real-env": "behavioral"})
    tags_after_tag = aa.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_tag.get("sim2real-env") == "behavioral", tags_after_tag
    analyzer_tags_after_tag = aa.get_analyzer(analyzerName=name)["analyzer"]["tags"]
    assert analyzer_tags_after_tag.get("sim2real-env") == "behavioral", analyzer_tags_after_tag

    aa.untag_resource(resourceArn=arn, tagKeys=["sim2real-env"])
    tags_after_untag = aa.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-env" not in tags_after_untag, tags_after_untag
    analyzer_tags_after_untag = aa.get_analyzer(analyzerName=name)["analyzer"]["tags"]
    assert "sim2real-env" not in analyzer_tags_after_untag, analyzer_tags_after_untag


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
