"""stale-parent-commit-id-rejected."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stale-parent-commit-id-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codecommit']

_STALE_PARENT_MESSAGE = (
    "The parent commit ID is not valid because it is not the current tip of the branch. "
    "You must provide the commit ID for the tip of the branch. The most common reason for "
    "this error is that your local repository is not synchronized to the latest changes in "
    "the AWS CodeCommit repository. Either synchronize your local repo by using the git pull "
    "command, or use GetBranch to retrieve the latest commit ID for the branch, and then try "
    "again."
)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutFile and DeleteFile naming a stale parentCommitId raise ParentCommitIdOutdatedException and
    leave the file and the tip untouched, while the identical PutFile naming the current tip commits."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"),
        tags={"sim2real": "stale-parent-commit-id-rejected"},
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo = meta["repositoryName"]

    v1 = b"version 1\n"
    v2 = b"version 2\n"
    v3 = b"version 3 -- the racing writer's payload\n"

    c1 = cc.put_file(
        repositoryName=repo, branchName="main", filePath="doc.txt",
        fileContent=v1, commitMessage="v1",
    )["commitId"]
    put2 = cc.put_file(
        repositoryName=repo, branchName="main", filePath="doc.txt",
        fileContent=v2, parentCommitId=c1, commitMessage="v2",
    )
    c2 = put2["commitId"]
    assert put2["blobId"] == _blob_sha1(v2), f"setup PutFile blobId {put2['blobId']!r}"

    # Break exactly one thing: name c1 as the parent, which is now one commit stale.
    try:
        cc.put_file(
            repositoryName=repo, branchName="main", filePath="doc.txt",
            fileContent=v3, parentCommitId=c1, commitMessage="v3 from a stale reader",
        )
        raise AssertionError(
            f"PutFile with the stale parent {c1} was accepted; the branch tip was {c2}. "
            "This silently overwrites a concurrent writer's commit."
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ParentCommitIdOutdatedException", (
            f"stale parentCommitId raised {code!r}, expected ParentCommitIdOutdatedException"
        )
        assert message == _STALE_PARENT_MESSAGE, (
            f"stale parentCommitId raised message {message!r}, expected {_STALE_PARENT_MESSAGE!r}"
        )

    # Effect absent: the file still holds v2 and the tip is still c2.
    still = cc.get_file(repositoryName=repo, commitSpecifier="main", filePath="doc.txt")
    assert still["fileContent"] == v2, (
        f"the rejected write changed the content to {still['fileContent']!r}; expected {v2!r}"
    )
    assert still["blobId"] == _blob_sha1(v2), (
        f"the rejected write changed the blob id to {still['blobId']!r}"
    )
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == c2, (
        "the rejected write advanced the branch tip"
    )

    # A DeleteFile carrying the same stale parent is rejected the same way, and the
    # path is still there afterwards.
    try:
        cc.delete_file(
            repositoryName=repo, branchName="main", filePath="doc.txt",
            parentCommitId=c1, commitMessage="delete from a stale reader",
        )
        raise AssertionError(f"DeleteFile with the stale parent {c1} was accepted")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ParentCommitIdOutdatedException", (
            f"stale parentCommitId on DeleteFile raised {code!r}, "
            "expected ParentCommitIdOutdatedException"
        )
        assert message == _STALE_PARENT_MESSAGE, (
            f"stale parentCommitId on DeleteFile raised message {message!r}, "
            f"expected {_STALE_PARENT_MESSAGE!r}"
        )
    assert cc.get_file(
        repositoryName=repo, commitSpecifier="main", filePath="doc.txt"
    )["fileContent"] == v2, "the rejected delete removed or altered the file"

    # Control: the identical write with the current tip as its parent succeeds.
    put3 = cc.put_file(
        repositoryName=repo, branchName="main", filePath="doc.txt",
        fileContent=v3, parentCommitId=c2, commitMessage="v3 from an up-to-date reader",
    )
    assert put3["blobId"] == _blob_sha1(v3), f"control PutFile blobId {put3['blobId']!r}"
    assert put3["commitId"] not in (c1, c2), f"control PutFile reused commit {put3['commitId']!r}"
    tip = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert tip == put3["commitId"], f"branch tip {tip!r} != the accepted commit {put3['commitId']!r}"
    assert cc.get_file(
        repositoryName=repo, commitSpecifier="main", filePath="doc.txt"
    )["fileContent"] == v3, "the accepted write did not take effect"


def _blob_sha1(content: bytes) -> str:
    """Git blob object id: sha1 of b'blob <bytelen>' + NUL + raw content.

    Not a security hash -- git's object-id construction is defined as SHA-1.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 - git object id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
