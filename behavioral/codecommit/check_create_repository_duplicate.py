"""create-repository-duplicate."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-repository-duplicate"
GROUP = 'error-semantics'
SERVICES = ['codecommit']


def _throttled_create(cc, name):
    # CodeCommit throttles control-plane mutations aggressively and the harness does no automatic
    # retry; a throttle here is environmental noise, not the behavior under test. Returns (metadata,
    # None, None) on success, else (None, error code, error message).
    code = message = None
    for _ in range(5):
        try:
            return cc.create_repository(repositoryName=name, tags={"sim2real": "ccdup"})["repositoryMetadata"], None, None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
        if code != "ThrottlingException":
            return None, code, message
        time.sleep(2)
    return None, code, message


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating an existing repository name is refused with RepositoryNameExistsException,
    the original repository is left unchanged (independent read), and once the name is freed
    by deleting the original the identical create succeeds again."""
    cc = ctx.client("codecommit")
    name = ctx.unique_name("sim2real-behav-repo-")
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=name))

    meta, code, _ = _throttled_create(cc, name)
    assert meta is not None, f"positive control failed: {code}"
    repo_id = meta["repositoryId"]

    dup_meta, code, message = _throttled_create(cc, name)
    assert dup_meta is None, "duplicate create unexpectedly succeeded"
    assert code == "RepositoryNameExistsException", code
    expected = f"Repository named {name} already exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: an independent read shows the original repository untouched — the
    # rejected duplicate did not create a second repository or advance any state.
    got = cc.get_repository(repositoryName=name)["repositoryMetadata"]
    assert got["repositoryId"] == repo_id, (repo_id, got["repositoryId"])
    assert got["creationDate"] == meta["creationDate"], "creation date changed — state advanced on a rejected create"

    # restore: free the name, confirmed by an independent read, then the identical
    # create must now succeed — proving the refusal was the name collision, not
    # something else (e.g. every CreateRepository call being blocked).
    cc.delete_repository(repositoryName=name)
    try:
        cc.get_repository(repositoryName=name)
        raise AssertionError("repository still visible via an independent read after delete")
    except ClientError as exc:
        gone_code = exc.response.get("Error", {}).get("Code")
        gone_message = exc.response.get("Error", {}).get("Message")
    assert gone_code == "RepositoryDoesNotExistException", gone_code
    gone_expected = f"{name} for {ctx.account}"
    assert gone_message == gone_expected, (
        f"expected message {gone_expected!r}, got {gone_message!r}"
    )

    recreated_meta, code, _ = _throttled_create(cc, name)
    assert recreated_meta is not None, f"identical create failed after the name was freed: {code}"
    assert recreated_meta["repositoryId"] != repo_id, "recreate returned the deleted repository's id"

    # terminal: an independent read at the destination confirms the recreated
    # repository is actually visible, not just accepted by its own response.
    got2 = cc.get_repository(repositoryName=name)["repositoryMetadata"]
    assert got2["repositoryId"] == recreated_meta["repositoryId"], got2

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
