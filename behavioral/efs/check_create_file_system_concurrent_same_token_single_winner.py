"""create-file-system-concurrent-same-token-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-file-system-concurrent-same-token-single-winner"
GROUP = "concurrency"
SERVICES = ["efs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateFileSystem calls with the same CreationToken produce exactly one winner."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-race-")

    def attempt(_i):
        try:
            resp = efs.create_file_system(
                CreationToken=token,
                Tags=[{"Key": "Name", "Value": token}, {"Key": "Owner", "Value": "sim2real"}],
            )
            return ("ok", resp["FileSystemId"], None)
        except ClientError as e:
            return (e.response["Error"]["Code"], e.response.get("FileSystemId"), e.response["Error"]["Message"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] != "ok"]

    assert len(winners) == 1, f"expected exactly one winner, got {winners} (all results: {results})"
    fs_id = winners[0][1]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))

    assert len(losers) == 7, f"expected exactly 7 losers among 8 concurrent attempts, got {losers}"
    for code, referenced_id, message in losers:
        assert code == "FileSystemAlreadyExists", f"expected FileSystemAlreadyExists, got {code}"
        expected = f"File system '{fs_id}' already exists with creation token '{token}'"
        assert message == expected, f"expected {expected!r}, got {message!r}"
        if referenced_id is not None:
            assert referenced_id == fs_id, f"loser error referenced {referenced_id}, winner was {fs_id}"

    # no duplicate file systems exist for this creation token
    matches = efs.describe_file_systems(CreationToken=token)["FileSystems"]
    assert len(matches) == 1, f"expected exactly one file system for token {token}, found {matches}"
    assert matches[0]["FileSystemId"] == fs_id, f"expected {fs_id}, describe returned {matches[0]['FileSystemId']}"


def _delete_fs_best_effort(efs, fs_id):
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            state = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "FileSystemNotFound":
                raise
            return
        if state == "available":
            break
        time.sleep(3.0)
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
