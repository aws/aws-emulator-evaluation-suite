"""update-repository-description-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-repository-description-reflected"
GROUP = 'lifecycle'
SERVICES = ['codecommit']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRepositoryDescription is persisted and echoed by GetRepository."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"),
        tags={"sim2real": "update-repo-desc"},
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    name = meta["repositoryName"]

    cc.update_repository_description(
        repositoryName=name, repositoryDescription="an updated description"
    )
    got = cc.get_repository(repositoryName=name)["repositoryMetadata"]
    assert got.get("repositoryDescription") == "an updated description", got

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
