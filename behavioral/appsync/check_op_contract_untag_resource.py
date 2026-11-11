"""op-contract-untag-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-untag-resource"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes the named tag key; NotFoundException on a well-formed but deleted resourceArn leaves the real resource's tags untouched."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real-remove-me": "yes", "sim2real-keep": "yes"},
    )["graphqlApi"]
    api_id = api["apiId"]
    arn = api["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    before = appsync.list_tags_for_resource(resourceArn=arn)["tags"]
    assert before == {"sim2real-remove-me": "yes", "sim2real-keep": "yes"}, before

    appsync.untag_resource(resourceArn=arn, tagKeys=["sim2real-remove-me"])
    after = appsync.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after == {"sim2real-keep": "yes"}, f"expected only sim2real-keep to remain, got {after}"

    ghost = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-ghost-"), authenticationType="API_KEY", tags={"x": "1"}
    )["graphqlApi"]
    ghost_arn = ghost["arn"]
    ghost_id = ghost["apiId"]
    appsync.delete_graphql_api(apiId=ghost_id)

    get_code, get_message = _error(lambda: appsync.get_graphql_api(apiId=ghost_id))
    assert get_code == "NotFoundException", f"expected NotFoundException, got {get_code}"
    assert get_message == "API not found.", get_message

    code, message = _error(lambda: appsync.untag_resource(resourceArn=ghost_arn, tagKeys=["x"]))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Resource was not found", message

    # the failed call targeted a different (nonexistent) resource; the real resource is unaffected
    still = appsync.list_tags_for_resource(resourceArn=arn)["tags"]
    assert still == {"sim2real-keep": "yes"}, still


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
