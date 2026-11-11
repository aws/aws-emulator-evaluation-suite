"""put-repository-catalog-data-freeform-architecture."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "put-repository-catalog-data-freeform-architecture"
GROUP = 'catalog-data'
SERVICES = ['ecr-public']

def _delete_repository_if_present(ecr, name):
    """Teardown: force-delete the repository, tolerating one the check already deleted in-band."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_repository_if_present(ecr, name))
    return name, resp


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRepositoryCatalogData accepts an architecture outside the documented set (no enum
    validation) and GetRepositoryCatalogData returns it verbatim.
    """
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)
    freeform = "NotARealArchitecture"

    ecr.put_repository_catalog_data(
        repositoryName=name,
        catalogData={"architectures": [freeform]},
    )

    got = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    assert freeform in got.get("architectures", []), (
        f"free-form architecture {freeform!r} did not round-trip: {got}"
    )

    ecr.delete_repository(repositoryName=name)

    read_error = _error(lambda: ecr.get_repository_catalog_data(repositoryName=name))
    assert read_error["Code"] == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException reading catalog data for a deleted "
        f"repository, got {read_error!r}"
    )
    expected = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert read_error["Message"] == expected, f"{read_error['Message']!r} != {expected!r}"

    write_error = _error(
        lambda: ecr.put_repository_catalog_data(
            repositoryName=name, catalogData={"architectures": [freeform]}
        )
    )
    assert write_error["Code"] == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException mutating catalog data for a deleted "
        f"repository, got {write_error!r}"
    )
    expected = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert write_error["Message"] == expected, f"{write_error['Message']!r} != {expected!r}"


def _error(fn) -> dict:
    """Call fn() and return the AWS Error (Code and Message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
