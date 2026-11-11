"""get-repository-catalog-data-nonexistent-repo-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-repository-catalog-data-nonexistent-repo-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRepositoryCatalogData fails RepositoryNotFoundException before the repository exists,
    returns empty catalogData once the same name is created, and returns data once it is set."""
    ecrp = _regional_client(ctx, "ecr-public")
    repo_name = ctx.unique_name("sim2real-behav-").lower()

    code, code_msg = _error_code(lambda: ecrp.get_repository_catalog_data(repositoryName=repo_name))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    expected_code_msg = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    # Catalog data is lazily populated: a repository with none set succeeds with an empty record.
    ecrp.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=repo_name, force=True))

    no_data_result = ecrp.get_repository_catalog_data(repositoryName=repo_name)
    empty_catalog_data = no_data_result["catalogData"]
    assert not empty_catalog_data.get("description"), (
        f"expected no description for a repo with no catalog data set, got {empty_catalog_data!r}"
    )

    ecrp.put_repository_catalog_data(
        repositoryName=repo_name,
        catalogData={"description": "sim2real behavioral fidelity check repository"},
    )
    result = ecrp.get_repository_catalog_data(repositoryName=repo_name)
    assert result["catalogData"]["description"] == "sim2real behavioral fidelity check repository", (
        f"expected description to reflect the explicit put, got {result['catalogData']!r}"
    )


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """ecr-public is operable only in us-east-1, so every target is called there."""
    from botocore.config import Config

    return ctx.client(
        service, region=region, config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
