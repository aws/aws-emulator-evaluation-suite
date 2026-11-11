"""op-contract-tag-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-tag-resource"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges valid tags with the creation tags; a reserved 'aws:' key (BadRequestException) and a
    well-formed nonexistent API ARN (NotFoundException) are rejected with their exact messages and leave the
    real API's tags untouched."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"), authenticationType="API_KEY", tags={"Existing": "yes"}
    )["graphqlApi"]
    api_id = api["apiId"]
    arn = api["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    appsync.tag_resource(resourceArn=arn, tags={"sim2real-env": "test"})
    tags_after_valid = appsync.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_valid.get("sim2real-env") == "test", (
        f"expected sim2real-env=test after a valid TagResource, got {tags_after_valid}"
    )
    assert tags_after_valid == {"Existing": "yes", "sim2real-env": "test"}, (
        f"expected TagResource to merge with the creation tags, got {tags_after_valid}"
    )

    code, message = _error(lambda: appsync.tag_resource(resourceArn=arn, tags={"aws:reserved": "x"}))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)", message

    tags_after_rejected = appsync.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "aws:reserved" not in tags_after_rejected, "rejected tag mutation was applied anyway"
    assert tags_after_rejected.get("sim2real-env") == "test", "prior valid tag was disturbed by the rejected call"

    bogus_arn = arn.rsplit("/", 1)[0] + "/zzzzzzzz00000000000000zzzz"
    code, message = _error(lambda: appsync.tag_resource(resourceArn=bogus_arn, tags={"X": "y"}))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Resource was not found", message

    # the refused call named a different, nonexistent resource; the real API's tags are unchanged
    still = appsync.list_tags_for_resource(resourceArn=arn)["tags"]
    assert still == {"Existing": "yes", "sim2real-env": "test"}, still


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
