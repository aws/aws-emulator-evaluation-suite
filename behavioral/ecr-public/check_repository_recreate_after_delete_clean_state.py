"""repository-recreate-after-delete-clean-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "repository-recreate-after-delete-clean-state"
GROUP = "state-machine"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so the client pins that
    region; ctx.client keeps an emulator run on the emulator's endpoint."""
    return ctx.client("ecr-public", region="us-east-1")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Recreating a repository with the same name after deletion starts with fresh, empty
    catalog data -- PutRepositoryCatalogData state from the prior repository does not leak
    across the delete/create boundary.
    """
    from botocore.exceptions import ClientError

    ecrpub = _ecrpub_client(ctx)
    repo_name = ctx.unique_name("sim2real-ecrpub-recreate-")

    ecrpub.create_repository(repositoryName=repo_name)
    secret_description = f"first-life-description-{ctx.unique_name('x')}"
    ecrpub.put_repository_catalog_data(
        repositoryName=repo_name,
        catalogData={"description": secret_description},
    )
    # Sanity: the catalog data really was set before we delete anything.
    first_life = ecrpub.get_repository_catalog_data(repositoryName=repo_name)
    assert first_life["catalogData"]["description"] == secret_description, (
        f"expected the just-written description {secret_description!r}, "
        f"got {first_life['catalogData']!r}"
    )

    ecrpub.delete_repository(repositoryName=repo_name)

    # The name is gone at the repository-existence level -- an independent read on the
    # just-deleted name fails with the specific not-found code, not a lingering ghost record.
    try:
        ecrpub.describe_repositories(repositoryNames=[repo_name])
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "RepositoryNotFoundException", (
            f"expected RepositoryNotFoundException for the just-deleted name {repo_name!r}, got {code}"
        )
        message = err.response["Error"]["Message"]
        expected = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
        assert message == expected, f"refusal message {message!r} != {expected!r}"
    else:
        raise AssertionError(
            f"expected describe_repositories({repo_name!r}) to fail after delete_repository"
        )

    # Recreate with the identical name.
    ecrpub.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecrpub.delete_repository(repositoryName=repo_name))

    # The repository exists again (fresh lifecycle instance).
    described = ecrpub.describe_repositories(repositoryNames=[repo_name])
    assert described["repositories"][0]["repositoryName"] == repo_name, (
        f"expected the recreated repository to describe as {repo_name!r}, "
        f"got {described['repositories'][0]!r}"
    )

    # The new instance has never had catalog data set on it -- the old description must not be
    # visible. GetRepositoryCatalogData on an existing repository with
    # no catalog data set returns HTTP 200 with an empty catalogData record, never
    # RepositoryCatalogDataNotFoundException here. What would prove a leak is the OLD description
    # surviving onto the fresh instance.
    second_life = ecrpub.get_repository_catalog_data(repositoryName=repo_name)
    assert not second_life["catalogData"].get("description"), (
        f"expected no description on the freshly recreated repository {repo_name!r}, "
        f"got {second_life['catalogData']!r} (prior-life value was {secret_description!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
