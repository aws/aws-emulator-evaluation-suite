"""create-repository-duplicate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-repository-duplicate"
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


_TAGS = [{"Key": "sim2real-managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}]


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
    kwargs.setdefault("tags", _TAGS)
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_if_exists(ecr, name))
    return name, resp


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRepository on a taken name is refused RepositoryAlreadyExistsException with the
    exact message and leaves one repository; once the original is deleted
    (RepositoryNotFoundException) the identical call succeeds."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    account = ctx.client("sts").get_caller_identity()["Account"]
    code, message = _err(lambda: ecr.create_repository(repositoryName=name))
    assert code == "RepositoryAlreadyExistsException", f"expected RepositoryAlreadyExistsException, got {code}"
    assert message == (
        f"The repository with name '{name}' already exists in the registry with id '{account}'"
    ), f"RepositoryAlreadyExistsException message: {message!r}"

    # Effect absent: the rejected call left exactly one repository behind, not two.
    described = ecr.describe_repositories(repositoryNames=[name])["repositories"]
    assert len(described) == 1, f"expected exactly 1 repository named {name!r}, got {len(described)}"

    # Restore: delete the original, freeing the name.
    ecr.delete_repository(repositoryName=name, force=True)
    gone_code, gone_message = _err(lambda: ecr.describe_repositories(repositoryNames=[name]))
    assert gone_code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException after delete, got {gone_code}"
    assert gone_message == (
        f"The repository with name '{name}' does not exist in the registry with id '{account}'"
    ), f"DescribeRepositories message: {gone_message!r}"

    # The identical call that was rejected a moment ago now succeeds.
    resp = ecr.create_repository(repositoryName=name, tags=_TAGS)
    assert resp["repository"]["repositoryName"] == name, resp["repository"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
