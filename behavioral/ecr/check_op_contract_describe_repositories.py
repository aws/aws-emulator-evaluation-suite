"""op-contract-describeRepositories."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describeRepositories"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRepositories returns exact metadata for valid names, but one nonexistent name in the
    filter fails the whole call with RepositoryNotFoundException and no repository data."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    repo_a = _create_repo(ctx)
    repo_b = _create_repo(ctx)
    name_a = repo_a["repositoryName"]
    name_b = repo_b["repositoryName"]

    # Positive control: valid multi-name filter succeeds and matches created repos.
    resp = ecr.describe_repositories(repositoryNames=[name_a, name_b])
    got = {r["repositoryName"]: r for r in resp["repositories"]}
    assert set(got) == {name_a, name_b}, f"expected {{name_a, name_b}}, got {set(got)}"
    assert got[name_a]["registryId"] == account_id, (
        f"expected registryId {account_id}, got {got[name_a]['registryId']}"
    )
    assert got[name_a]["imageTagMutability"] == "MUTABLE", (
        f"expected MUTABLE, got {got[name_a]['imageTagMutability']}"
    )

    # Negative: mixing in a nonexistent name fails the entire call.
    missing_name = ctx.unique_name("sim2real-ecr-missing-")
    caught = {}
    try:
        result = ecr.describe_repositories(repositoryNames=[name_a, missing_name])
    except ClientError as exc:
        caught["code"] = exc.response["Error"]["Code"]
        caught["response"] = exc.response
    else:
        raise AssertionError(
            f"expected RepositoryNotFoundException, but the call SUCCEEDED and returned {result!r}"
        )
    assert caught.get("code") == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException, got {caught.get('code')}"
    )
    expected = f"The repository with name '{missing_name}' does not exist in the registry with id '{account_id}'"
    message = caught["response"]["Error"].get("Message")
    assert message == expected, f"expected {expected!r}, got {message!r}"
    # No repositories key leaked on the exception response -- the call produced no data.
    assert "repositories" not in caught["response"], (
        f"expected no 'repositories' key on the error response, got {caught['response']!r}"
    )


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
