"""tag-value-empty-string-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-empty-string-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An empty-string tag value round-trips as "" and stays distinct from a never-set key, and
    UntagResource removes only the key it was asked to remove."""
    appsync = ctx.client("appsync")

    api_name = ctx.unique_name("sim2real-tagapi-")
    api = appsync.create_graphql_api(name=api_name, authenticationType="API_KEY")["graphqlApi"]
    api_id = api["apiId"]
    resource_arn = api["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    appsync.tag_resource(resourceArn=resource_arn, tags={"EmptyTag": "", "PresentTag": "some-value"})

    tags_after_create = appsync.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    assert "EmptyTag" in tags_after_create, tags_after_create
    assert tags_after_create["EmptyTag"] == "", (
        f"expected EmptyTag value '' preserved, got {tags_after_create['EmptyTag']!r}"
    )
    assert tags_after_create["PresentTag"] == "some-value", (
        f"expected PresentTag value 'some-value', got {tags_after_create['PresentTag']!r}"
    )
    # A key that was never set must be genuinely absent, not present-with-empty-value.
    assert "NeverSetTag" not in tags_after_create, (
        f"expected NeverSetTag absent, got present with value {tags_after_create.get('NeverSetTag')!r}"
    )

    appsync.untag_resource(resourceArn=resource_arn, tagKeys=["EmptyTag"])

    tags_after_untag = appsync.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    assert "EmptyTag" not in tags_after_untag, tags_after_untag
    assert tags_after_untag["PresentTag"] == "some-value", (
        f"expected PresentTag to survive UntagResource(EmptyTag) untouched, got {tags_after_untag['PresentTag']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
