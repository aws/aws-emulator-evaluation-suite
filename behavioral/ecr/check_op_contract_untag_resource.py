"""op-contract-untag-resource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-untag-resource"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested tag key and leaves the rest; an ARN for a missing
    repository fails with RepositoryNotFoundException and leaves the real repository's tags."""
    ecr = ctx.client("ecr")

    repo_name = ctx.unique_name("sim2real-ecr-untag-")
    create_resp = ecr.create_repository(
        repositoryName=repo_name,
        tags=[
            {"Key": "team", "Value": "platform"},
            {"Key": "env", "Value": "test"},
            {"Key": "temp", "Value": "delete-me"},
        ],
    )
    repo_arn = create_resp["repository"]["repositoryArn"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    initial_tags = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=repo_arn)["tags"]}
    assert initial_tags == {"team": "platform", "env": "test", "temp": "delete-me"}, initial_tags

    ecr.untag_resource(resourceArn=repo_arn, tagKeys=["temp"])
    after_untag = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=repo_arn)["tags"]}
    assert after_untag == {"team": "platform", "env": "test"}, after_untag

    bogus_arn = repo_arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("sim2real-ecr-missing-")
    code, message = _client_error(
        lambda: ecr.untag_resource(resourceArn=bogus_arn, tagKeys=["team"])
    )
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert message == (
        f"The repository with name '{bogus_arn.rsplit('/', 1)[1]}' does not exist in the registry with id '{ctx.account}'"
    ), message

    unchanged = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(resourceArn=repo_arn)["tags"]}
    assert unchanged == {"team": "platform", "env": "test"}, unchanged


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
