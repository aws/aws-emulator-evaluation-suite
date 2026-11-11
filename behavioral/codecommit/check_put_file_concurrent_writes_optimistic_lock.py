"""put-file-concurrent-writes-optimistic-lock."""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "put-file-concurrent-writes-optimistic-lock"
GROUP = "data-plane"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of concurrent PutFile calls on one path naming the same parentCommitId exactly one wins and the
    rest raise ParentCommitIdOutdatedException; the branch tip is the winner's commit and the file
    holds its bytes and git blob id."""
    cc = ctx.client("codecommit")

    repo_name = ctx.unique_name("sim2real-cc-race-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    base = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="counter.txt",
        fileContent=b"0",
    )["commitId"]

    racer_count = 6
    payloads = {i: f"racer-{i}".encode() for i in range(racer_count)}
    results: list[tuple[int, str | None, str | None, str | None]] = []

    def racer(i: int):
        try:
            resp = cc.put_file(
                repositoryName=repo_name,
                branchName="main",
                filePath="counter.txt",
                fileContent=payloads[i],
                parentCommitId=base,
            )
            return (i, resp["commitId"], resp["blobId"], None)
        except Exception as exc:  # noqa: BLE001
            error = getattr(exc, "response", {}).get("Error", {})
            return (i, None, None, (error.get("Code"), error.get("Message")))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(racer, i) for i in range(racer_count)]
        for f in as_completed(futures):
            results.append(f.result())

    successes = [r for r in results if r[1] is not None]
    failures = [r for r in results if r[1] is None]

    assert len(successes) == 1, (
        f"expected exactly 1 racer to win among {racer_count}, got {len(successes)}: {successes}"
    )
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {failures}"
    )
    outdated = (
        "ParentCommitIdOutdatedException",
        "The parent commit ID is not valid because it is not the current tip of the branch. You must "
        "provide the commit ID for the tip of the branch. The most common reason for this error is "
        "that your local repository is not synchronized to the latest changes in the AWS CodeCommit "
        "repository. Either synchronize your local repo by using the git pull command, or use "
        "GetBranch to retrieve the latest commit ID for the branch, and then try again.",
    )
    for _, _, _, refusal in failures:
        assert refusal == outdated, (
            f"loser raised {refusal!r}, expected {outdated!r}"
        )

    winner_idx, winning_commit_id, winning_blob_id, _ = successes[0]
    expected_blob_id = _blob_sha1(payloads[winner_idx])
    assert winning_blob_id == expected_blob_id, (
        f"winning PutFile blobId {winning_blob_id!r} != sha1 git object id of its own payload "
        f"{expected_blob_id!r}"
    )

    branch_tip = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]["commitId"]
    assert branch_tip == winning_commit_id, (
        f"branch tip {branch_tip!r} != the only accepted commit {winning_commit_id!r}"
    )

    tip_file = cc.get_file(repositoryName=repo_name, commitSpecifier="main", filePath="counter.txt")
    assert tip_file["fileContent"] == payloads[winner_idx], (
        f"counter.txt at the tip holds {tip_file['fileContent']!r}, expected the winner's payload "
        f"{payloads[winner_idx]!r}"
    )
    assert tip_file["blobId"] == expected_blob_id, (
        f"GetFile blobId {tip_file['blobId']!r} != sha1 git object id of the winner's payload "
        f"{expected_blob_id!r}"
    )


def _blob_sha1(content: bytes) -> str:
    """Git blob object id: sha1 of b'blob <bytelen>' + NUL + raw content.

    Not a security hash -- git's object-id construction is defined as SHA-1.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 - git object id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
