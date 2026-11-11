"""tag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-rejected"
GROUP = "representation"
SERVICES = ["config"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on a well-formed but nonexistent stored-query ARN fail with
    ResourceNotFoundException and its exact message, while tagging a real stored query reads back
    {"k": "v"}."""
    cfg = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_query_name = ctx.unique_name("sim2real-bogus-query-")
    bogus_arn = (
        f"arn:aws:config:{ctx.region}:{account_id}:stored-query/{bogus_query_name}/"
        f"query-{'0' * 12}"
    )

    expected_message = f"Resource {bogus_arn} does not exist for account {account_id}"
    code, message = _error(
        lambda: cfg.tag_resource(ResourceArn=bogus_arn, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: querying tags for the nonexistent resource still 404s (no tag
    # record was ever created for it).
    code, message = _error(lambda: cfg.list_tags_for_resource(ResourceArn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: tagging a resource that actually exists succeeds.
    real_query_name = ctx.unique_name("sim2real-realquery-").replace("_", "-")
    real_arn = cfg.put_stored_query(
        StoredQuery={
            "QueryName": real_query_name,
            "Expression": "SELECT resourceId WHERE resourceType = 'AWS::S3::Bucket'",
        }
    )["QueryArn"]
    ctx.on_cleanup(lambda: cfg.delete_stored_query(QueryName=real_query_name))

    cfg.tag_resource(ResourceArn=real_arn, Tags=[{"Key": "k", "Value": "v"}])
    tags = {t["Key"]: t["Value"] for t in cfg.list_tags_for_resource(ResourceArn=real_arn)["Tags"]}
    assert tags == {"k": "v"}, f"expected positive-control tags {{'k': 'v'}}, got {tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
