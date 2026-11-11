"""update-repository-name-reflected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-repository-name-reflected"
GROUP = 'lifecycle'
SERVICES = ['codecommit']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRepositoryName renames in place: the new name resolves and the old
    name no longer exists."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "ccupdname"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    old = meta["repositoryName"]
    new = ctx.unique_name("sim2real-behav-repo-renamed-")

    cc.update_repository_name(oldName=old, newName=new)
    # keep cleanup honest: the resource now answers to the new name
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=new))

    got = cc.get_repository(repositoryName=new)["repositoryMetadata"]
    assert got["repositoryName"] == new, got

    try:
        cc.get_repository(repositoryName=old)
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "RepositoryDoesNotExistException", code
    expected_message = f"{old} for {ctx.account}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
