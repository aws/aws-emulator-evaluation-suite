"""tag-resource-list-untag-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-untag-round-trip"
GROUP = "state"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a live GraphQL
    API: tags actually persist and individual keys can be selectively removed
    without disturbing the others."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    arn = api["arn"]

    appsync.tag_resource(resourceArn=arn, tags={"Env": "sim2real-test", "Owner": "sim2real"})
    tags = appsync.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("Env") == "sim2real-test", tags
    assert tags.get("Owner") == "sim2real", tags

    appsync.untag_resource(resourceArn=arn, tagKeys=["Env"])
    tags2 = appsync.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "Env" not in tags2, f"Env should have been removed: {tags2}"
    assert tags2.get("Owner") == "sim2real", f"Owner should remain untouched: {tags2}"


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"), authenticationType=auth_type
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
