"""batch-get-repository-scanning-configuration-missing-repo."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-repository-scanning-configuration-missing-repo"
GROUP = 'error-semantics'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """BatchGetRepositoryScanningConfiguration reports REPOSITORY_NOT_FOUND for a missing repository
    while still returning the configuration of an existing one in the same call."""
    ecr = ctx.client("ecr")

    existing = ctx.unique_name("sim2real-behav-ecr-present-")
    ecr.create_repository(repositoryName=existing)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=existing, force=True))

    missing = ctx.unique_name("sim2real-behav-ecr-absent-")
    resp = ecr.batch_get_repository_scanning_configuration(
        repositoryNames=[existing, missing]
    )

    configs = {c["repositoryName"]: c for c in resp["scanningConfigurations"]}
    assert set(configs) == {existing}, resp["scanningConfigurations"]
    assert configs[existing]["repositoryArn"].endswith(f"repository/{existing}"), configs[existing]

    assert len(resp["failures"]) == 1, resp["failures"]
    failure = resp["failures"][0]
    assert failure["repositoryName"] == missing, failure
    assert failure["failureCode"] == "REPOSITORY_NOT_FOUND", failure

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
