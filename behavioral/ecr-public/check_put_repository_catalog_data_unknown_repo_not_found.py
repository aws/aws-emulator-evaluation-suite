"""put-repository-catalog-data-unknown-repo-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-repository-catalog-data-unknown-repo-not-found"
GROUP = "error-semantics"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRepositoryCatalogData on a nonexistent repository fails RepositoryNotFoundException, and
    GetRepositoryCatalogData on that name also finds none; on a real repository the call succeeds."""
    ecrp = _regional_client(ctx, "ecr-public")

    control_name = ctx.unique_name("sim2real-behav-ecrp-catalog-control-")
    ecrp.create_repository(
        repositoryName=control_name,
        tags=[{"Key": "sim2real-managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=control_name, force=True))
    ecrp.put_repository_catalog_data(
        repositoryName=control_name, catalogData={"description": "control"}
    )
    control = ecrp.get_repository_catalog_data(repositoryName=control_name)
    assert control["catalogData"]["description"] == "control", (
        f"positive control: expected the description just set, got {control['catalogData']!r}"
    )

    bogus = ctx.unique_name("sim2real-behav-ecrp-catalog-missing-")
    error = _error(
        lambda: ecrp.put_repository_catalog_data(
            repositoryName=bogus, catalogData={"description": "x"}
        )
    )
    assert error["Code"] == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException, got {error!r}"
    )
    expected = f"The repository with name '{bogus}' does not exist in the registry with id '{ctx.account}'"
    assert error["Message"] == expected, f"refusal message {error['Message']!r} != {expected!r}"

    read_error = _error(lambda: ecrp.get_repository_catalog_data(repositoryName=bogus))
    assert read_error["Code"] == "RepositoryNotFoundException", (
        f"expected the missing repo to also 404 on an independent read, got {read_error!r}"
    )
    expected = f"The repository with name '{bogus}' does not exist in the registry with id '{ctx.account}'"
    assert read_error["Message"] == expected, f"{read_error['Message']!r} != {expected!r}"


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """A ctx client for ``service``, pinned by default to us-east-1, the only ecr-public region."""
    return ctx.client(service, region=region)


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
