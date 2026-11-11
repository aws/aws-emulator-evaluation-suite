"""create-repository-basic."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-repository-basic"
GROUP = 'repository-lifecycle'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(), which must fail; return its (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_if_exists(ecr, name):
    """Teardown: force-delete the repository, tolerating one the check already deleted."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(
        repositoryName=name,
        tags=[{"Key": "sim2real", "Value": "create-repository-basic"}],
        **kwargs,
    )
    ctx.on_cleanup(lambda: _delete_if_exists(ecr, name))
    return name, resp


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRepository transitions nonexistent -> created (empty), visible in DescribeRepositories, then DeleteRepository removes it and the deleted repository can no longer be mutated."""
    ecr = ctx.client("ecr-public")
    name, resp = _create_repository(ctx, ecr)
    repo = resp["repository"]
    assert repo["repositoryName"] == name, f"expected repositoryName {name!r}, got {repo['repositoryName']!r}"
    assert repo.get("repositoryArn"), f"expected a non-empty repositoryArn, got {repo.get('repositoryArn')!r}"
    assert repo.get("repositoryUri"), f"expected a non-empty repositoryUri, got {repo.get('repositoryUri')!r}"

    described = ecr.describe_repositories(repositoryNames=[name])
    names = [r["repositoryName"] for r in described["repositories"]]
    assert name in names, f"expected {name!r} in DescribeRepositories, got {names!r}"

    ecr.delete_repository(repositoryName=name)
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"The repository with name '{name}' does not exist in the registry with id '{account}'"
    )
    code, message = _err(lambda: ecr.describe_repositories(repositoryNames=[name]))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert message == not_found, f"DescribeRepositories message: {message!r}"

    # The delete didn't just make the repository invisible -- it's gone enough that a further
    # mutation on the same identifier is rejected the same way, not silently accepted or 500'd.
    second_delete_code, second_delete_message = _err(lambda: ecr.delete_repository(repositoryName=name))
    assert second_delete_code == "RepositoryNotFoundException", (
        f"expected a delete on the already-deleted {name!r} to fail RepositoryNotFoundException, "
        f"got {second_delete_code}"
    )
    assert second_delete_message == not_found, f"DeleteRepository message: {second_delete_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
