"""repository-catalog-data-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "repository-catalog-data-lifecycle"
GROUP = 'catalog-data'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(); return the botocore Error (Code and Message) if a ClientError is raised. An
    unexpected SUCCESS raises, so a target that accepts what AWS refuses cannot read as a code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    resp = ecr.create_repository(
        repositoryName=name,
        tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
        **kwargs,
    )
    ctx.on_cleanup(lambda: _delete_repository_if_present(ecr, name))
    return name, resp


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRepositoryCatalogData is read back by GetRepositoryCatalogData; after DeleteRepository
    both the read and a new put are refused RepositoryNotFoundException with the exact message."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    ecr.put_repository_catalog_data(
        repositoryName=name,
        catalogData={
            "description": "behavioral fidelity test repo",
            "architectures": ["ARM 64"],
            "operatingSystems": ["Linux"],
        },
    )

    got = ecr.get_repository_catalog_data(repositoryName=name)
    data = got["catalogData"]
    assert data["description"] == "behavioral fidelity test repo", data
    assert "ARM 64" in data.get("architectures", []), data
    assert "Linux" in data.get("operatingSystems", []), data

    ecr.delete_repository(repositoryName=name)

    # --- gone and unusable: an independent read at the destination ---------------------
    error = _err(lambda: ecr.get_repository_catalog_data(repositoryName=name))
    assert error["Code"] == "RepositoryNotFoundException", (
        f"GetRepositoryCatalogData on a deleted repository must fail with "
        f"RepositoryNotFoundException; got {error!r}"
    )
    expected = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert error["Message"] == expected, f"{error['Message']!r} != {expected!r}"

    # --- gone and unusable: a mutation against the dead name also fails ----------------
    error = _err(
        lambda: ecr.put_repository_catalog_data(
            repositoryName=name,
            catalogData={"description": "should not be storable after delete"},
        )
    )
    assert error["Code"] == "RepositoryNotFoundException", (
        f"PutRepositoryCatalogData on a deleted repository must fail with "
        f"RepositoryNotFoundException; got {error!r}"
    )
    expected = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert error["Message"] == expected, f"{error['Message']!r} != {expected!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
