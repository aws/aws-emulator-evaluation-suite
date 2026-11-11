"""op-contract-tag-resource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-tag-resource"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource: success path attaches tags that are then visible via ListTagsForResource;
    a tag key using the reserved 'aws:' prefix is rejected with InvalidTagParameterException
    and leaves the resource's existing tags completely unchanged."""
    ecr = ctx.client("ecr")

    repo_name = ctx.unique_name("sim2real-ecr-tag-")
    create_resp = ecr.create_repository(repositoryName=repo_name)
    repo_arn = create_resp["repository"]["repositoryArn"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    # --- success path ---
    ecr.tag_resource(
        resourceArn=repo_arn,
        tags=[{"Key": "team", "Value": "platform"}, {"Key": "env", "Value": "test"}],
    )
    tags_after = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=repo_arn)["tags"]}
    assert tags_after == {"team": "platform", "env": "test"}, tags_after

    # --- error boundary: reserved "aws:" tag-key prefix is rejected ---
    code, message = _client_error(
        lambda: ecr.tag_resource(
            resourceArn=repo_arn, tags=[{"Key": "aws:reserved", "Value": "nope"}]
        )
    )
    assert code == "InvalidTagParameterException", f"expected InvalidTagParameterException, got {code}"
    assert message == (
        "Caller is an end user and not allowed to mutate system tags"
    ), message

    # the resource's tag set must be exactly what it was before the rejected call
    tags_unchanged = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=repo_arn)["tags"]}
    assert tags_unchanged == {"team": "platform", "env": "test"}, tags_unchanged

    # --- distinct not-found boundary: resourceArn pointing at a nonexistent repository ---
    bogus_arn = repo_arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("sim2real-ecr-missing-")
    code2, message2 = _client_error(
        lambda: ecr.tag_resource(resourceArn=bogus_arn, tags=[{"Key": "x", "Value": "y"}])
    )
    assert code2 == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code2}"
    assert message2 == (
        f"The repository with name '{bogus_arn.rsplit('/', 1)[1]}' does not exist in the registry with id '{ctx.account}'"
    ), message2

    # the real repository's tags must be completely unaffected by the failed call on the bogus ARN
    tags_still_unchanged = {
        t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=repo_arn)["tags"]
    }
    assert tags_still_unchanged == {"team": "platform", "env": "test"}, tags_still_unchanged


def _client_error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
