"""delete-repository-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-repository-not-found"
GROUP = 'error-semantics'
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
    """Teardown: force-delete the repository, tolerating one that is already gone."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRepository on a missing name is refused RepositoryNotFoundException with the exact
    message and creates nothing (DescribeRepositories gives the same error), while a real
    repository deletes and is then not found the same way."""
    ecr = ctx.client("ecr-public")
    bogus = ctx.unique_name("sim2real-behav-ecrpub-nonexistent-")
    account = ctx.client("sts").get_caller_identity()["Account"]

    def not_found(repository_name):
        return (
            f"The repository with name '{repository_name}' does not exist in the registry "
            f"with id '{account}'"
        )

    code, message = _err(lambda: ecr.delete_repository(repositoryName=bogus))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert message == not_found(bogus), f"DeleteRepository message: {message!r}"

    # Effect absent: the rejected delete must not have fabricated the repository as a
    # side effect -- an independent read still sees it as never-created.
    describe_code, describe_message = _err(lambda: ecr.describe_repositories(repositoryNames=[bogus]))
    assert describe_code == "RepositoryNotFoundException", (
        f"expected the bogus repo to remain absent, got {describe_code}"
    )
    assert describe_message == not_found(bogus), f"DescribeRepositories message: {describe_message!r}"

    # Positive control: a real repository can be deleted successfully, and is then gone.
    real_name = ctx.unique_name("sim2real-behav-ecrpub-real-")
    ecr.create_repository(repositoryName=real_name)
    ctx.on_cleanup(lambda: _delete_if_exists(ecr, real_name))

    ecr.delete_repository(repositoryName=real_name)

    after_code, after_message = _err(lambda: ecr.describe_repositories(repositoryNames=[real_name]))
    assert after_code == "RepositoryNotFoundException", (
        f"expected the real repo to be gone after delete, got {after_code}"
    )
    assert after_message == not_found(real_name), f"DescribeRepositories message: {after_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
