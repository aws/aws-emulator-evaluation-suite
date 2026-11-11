"""op-contract-listTagsForResource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listTagsForResource"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource returns the tags a GraphQL API was created with; a non-AppSync resourceArn is
    rejected with BadRequestException and the ARN of a deleted API with NotFoundException, each with its
    exact message."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-appsync-")
    resp = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"Team": "checkout", "Env": "test"}
    )
    api_id = resp["graphqlApi"]["apiId"]
    arn = resp["graphqlApi"]["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    tags = appsync.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"Team": "checkout", "Env": "test"}, tags

    # The resourceArn parameter has a client-side minimum-length constraint (matching the
    # length of a well-formed AppSync ARN); a short/malformed value fails botocore's local
    # param validation before it ever reaches AWS. Use a value that is long enough to clear
    # that local check but is still not a valid AppSync resource ARN, so we exercise the
    # server-side BadRequestException.
    code, message = _error_code(
        lambda: appsync.list_tags_for_resource(
            resourceArn="arn:aws:s3:::not-an-appsync-resource-padded-to-clear-the-minimum-arn-length-check"
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected_message = "Invalid input resource arn: expected vendor appsync"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # A well-formed AppSync ARN whose API was deleted is not found.
    ghost_arn = _ghost_api_arn(ctx, appsync)
    code, message = _error_code(lambda: appsync.list_tags_for_resource(resourceArn=ghost_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Resource was not found", f"unexpected message: {message!r}"


def _ghost_api_arn(ctx, appsync) -> str:
    """Create a GraphQL API and delete it; return its ARN."""
    ghost = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-ghost-"), authenticationType="API_KEY"
    )["graphqlApi"]
    ctx.on_cleanup(lambda: _delete_api_if_present(appsync, ghost["apiId"]))
    appsync.delete_graphql_api(apiId=ghost["apiId"])
    return ghost["arn"]


def _delete_api_if_present(appsync, api_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.delete_graphql_api(apiId=api_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
