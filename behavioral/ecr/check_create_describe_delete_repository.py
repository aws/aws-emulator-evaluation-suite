"""create-describe-delete-repository."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _delete_repo_if_present(ecr, name))
    return resp["repository"]

def _delete_repo_if_present(ecr, name):
    """Teardown: force-delete `name`, tolerating a repository the check already deleted."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise

CHECK = "create-describe-delete-repository"
GROUP = 'repository-lifecycle'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRepository -> exists with expected defaults -> DeleteRepository removes it."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    repo = _create_repo(ecr, ctx, name)
    assert repo["repositoryName"] == name, f"expected name {name}, got {repo['repositoryName']}"
    assert repo["repositoryUri"].endswith("/" + name), f"uri does not end with repo name: {repo['repositoryUri']}"
    expected_arn = f"arn:aws:ecr:{ctx.region}:{ctx.account}:repository/{name}"
    assert repo["repositoryArn"] == expected_arn, f"expected ARN {expected_arn}, got {repo['repositoryArn']}"
    assert repo["imageTagMutability"] == "MUTABLE", f"expected MUTABLE default, got {repo['imageTagMutability']}"

    described = ecr.describe_repositories(repositoryNames=[name])["repositories"]
    assert len(described) == 1, f"expected exactly 1 repository named {name}, got {len(described)}"
    assert described[0]["repositoryArn"] == repo["repositoryArn"], (
        f"describe ARN {described[0]['repositoryArn']} != create ARN {repo['repositoryArn']}"
    )

    def _listed():
        return [
            r["repositoryName"]
            for page in ecr.get_paginator("describe_repositories").paginate()
            for r in page["repositories"]
        ]

    assert name in _listed(), "the live repository is not listed by DescribeRepositories"

    ecr.delete_repository(repositoryName=name, force=True)

    code, status, message = _error(lambda: ecr.describe_repositories(repositoryNames=[name]))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx on describe of the deleted repository, got {status}"
    expected_message = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Gone beat 2: the unfiltered paginated listing no longer contains the name.
    assert name not in _listed(), "the deleted repository is still listed by DescribeRepositories"

    # The deleted id is not just absent from reads, it also rejects a further mutation.
    code, status, message = _error(
        lambda: ecr.put_image_tag_mutability(repositoryName=name, imageTagMutability="IMMUTABLE")
    )
    assert code == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException on PutImageTagMutability of the deleted repository, got {code}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx on PutImageTagMutability of the deleted repository, got {status}"
    expected_message = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
