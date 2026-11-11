"""op-contract-listTagsForResource."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listTagsForResource"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource returns exactly the tags applied at creation and reflects a
    subsequent TagResource call; it raises RepositoryNotFoundException for a resourceArn
    pointing at a repository that does not exist."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    repo = _create_repo(ctx, tags=[{"Key": "env", "Value": "sim2real-test"}])
    arn = repo["repositoryArn"]

    resp = ecr.list_tags_for_resource(resourceArn=arn)
    assert resp["tags"] == [{"Key": "env", "Value": "sim2real-test"}], resp["tags"]

    ecr.tag_resource(resourceArn=arn, tags=[{"Key": "owner", "Value": "sim2real"}])
    resp2 = ecr.list_tags_for_resource(resourceArn=arn)
    got = {(t["Key"], t["Value"]) for t in resp2["tags"]}
    assert got == {("env", "sim2real-test"), ("owner", "sim2real")}, got

    missing_name = ctx.unique_name("sim2real-ecr-missing-")
    missing_arn = f"arn:aws:ecr:{ctx.region}:{account_id}:repository/{missing_name}"
    code, message = _error_code(lambda: ecr.list_tags_for_resource(resourceArn=missing_arn))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    expected_message = (
        f"The repository with name '{missing_name}' does not exist in the registry with id "
        f"'{account_id}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
