"""tag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via GetTags, and UntagResource removes them
    while leaving unrelated tags intact."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-tags-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"

    before = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert before == {}, f"expected no tags on a freshly created API, got {before}"

    apigw.tag_resource(resourceArn=resource_arn, tags={"Environment": "test", "Team": "sim2real"})

    after_tag = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert after_tag.get("Environment") == "test", after_tag
    assert after_tag.get("Team") == "sim2real", after_tag

    apigw.untag_resource(resourceArn=resource_arn, tagKeys=["Environment"])

    after_untag = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert "Environment" not in after_untag, after_untag
    assert after_untag.get("Team") == "sim2real", "unrelated tag must survive selective untag"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
