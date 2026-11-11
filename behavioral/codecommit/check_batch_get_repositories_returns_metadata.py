"""batch-get-repositories-returns-metadata."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-repositories-returns-metadata"
GROUP = 'lifecycle'
SERVICES = ['codecommit']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetRepositories returns full metadata for existing repos and reports
    absent ones out-of-band (no exception)."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "ccbgr"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    name = meta["repositoryName"]
    absent = ctx.unique_name("sim2real-behav-missing-")

    resp = cc.batch_get_repositories(repositoryNames=[name, absent])
    by_name = {r["repositoryName"]: r for r in resp.get("repositories", [])}
    assert name in by_name, resp
    assert by_name[name]["Arn"] == meta["Arn"], by_name[name]
    # Absent repo must NOT appear as a materialized repository ...
    assert absent not in by_name, resp
    # ... and must be reported out-of-band via repositoriesNotFound, not just
    # silently dropped from `repositories`.
    assert absent in resp.get("repositoriesNotFound", []), resp

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
