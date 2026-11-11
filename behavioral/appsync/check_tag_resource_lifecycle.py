"""tag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle"
GROUP = 'tags'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGraphqlApi tags appear in ListTagsForResource; TagResource/UntagResource mutate them."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY", tags={"env": "test"})["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    arn = api["arn"]

    tags = svc.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"env": "test"}, f"expected only the creation-time tag, got {tags}"

    svc.tag_resource(resourceArn=arn, tags={"team": "qa"})
    tags2 = svc.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags2 == {"env": "test", "team": "qa"}, f"expected both tags after TagResource, got {tags2}"

    svc.untag_resource(resourceArn=arn, tagKeys=["team"])
    tags3 = svc.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags3 == {"env": "test"}, f"expected only env to remain after UntagResource, got {tags3}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
