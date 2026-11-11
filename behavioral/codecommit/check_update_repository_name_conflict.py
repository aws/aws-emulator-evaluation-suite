"""update-repository-name-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-repository-name-conflict"
GROUP = 'error-semantics'
SERVICES = ['codecommit']


def _error(fn):
    """Call fn(); return the (code, message) it raised. An unexpected SUCCESS raises, because an
    emulator accepting a call AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRepositoryName onto a name already in use -> RepositoryNameExistsException,
    the source repo keeps its own name, and the identical rename succeeds once the
    conflicting name is freed."""
    cc = ctx.client("codecommit")

    current_a = {"name": ctx.unique_name("sim2real-behav-repo-a-")}
    cc.create_repository(repositoryName=current_a["name"])
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=current_a["name"]))

    name_b = ctx.unique_name("sim2real-behav-repo-b-")
    cc.create_repository(repositoryName=name_b)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=name_b))

    # Positive control: an uncontested rename succeeds, and an independent read
    # confirms the move — the new name resolves, the old one is gone — before we
    # probe the conflict. Without this, "rejects a colliding name" is
    # indistinguishable from "rejects every rename".
    renamed_a = ctx.unique_name("sim2real-behav-repo-a2-")
    old_a = current_a["name"]
    cc.update_repository_name(oldName=old_a, newName=renamed_a)
    current_a["name"] = renamed_a
    got = cc.get_repository(repositoryName=renamed_a)["repositoryMetadata"]
    assert got["repositoryName"] == renamed_a, got
    gone_code, gone_message = _error(lambda: cc.get_repository(repositoryName=old_a))
    assert gone_code == "RepositoryDoesNotExistException", gone_code
    expected_gone = f"{old_a} for {ctx.account}"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

    # Break: rename A onto B's existing name -> conflict.
    conflict_code, conflict_message = _error(
        lambda: cc.update_repository_name(oldName=current_a["name"], newName=name_b)
    )
    assert conflict_code == "RepositoryNameExistsException", conflict_code
    expected_conflict = f"Repository named {name_b} already exists"
    assert conflict_message == expected_conflict, (
        f"expected message {expected_conflict!r}, got {conflict_message!r}"
    )

    # Effect absent, via an independent read: A still answers to its own name and
    # B is untouched — the rejected rename moved nothing.
    got_a = cc.get_repository(repositoryName=current_a["name"])["repositoryMetadata"]
    assert got_a["repositoryName"] == current_a["name"], got_a
    got_b = cc.get_repository(repositoryName=name_b)["repositoryMetadata"]
    assert got_b["repositoryName"] == name_b, got_b

    # Restore: free the conflicting name.
    cc.delete_repository(repositoryName=name_b)

    # The identical rename now succeeds.
    cc.update_repository_name(oldName=current_a["name"], newName=name_b)
    current_a["name"] = name_b
    got_final = cc.get_repository(repositoryName=name_b)["repositoryMetadata"]
    assert got_final["repositoryName"] == name_b, got_final

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
