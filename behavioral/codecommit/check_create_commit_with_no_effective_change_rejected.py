"""create-commit-with-no-effective-change-rejected."""
from __future__ import annotations

import binascii
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-commit-with-no-effective-change-rejected"
GROUP = 'error-semantics'
SERVICES = ['codecommit']


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateCommit whose putFiles reproduce the exact bytes already at those paths is
    refused with NoChangeException and the branch tip and tree id are untouched, while a
    one-byte change in the same request shape is accepted."""
    cc = ctx.client("codecommit")

    repo = ctx.unique_name("sim2real-behav-ccnochg-")
    cc.create_repository(repositoryName=repo, tags={"sim2real": "ccnochg"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    one = b"first file\n"
    two = b"second file\n"
    one_changed = b"First file\n"  # exactly one byte differs

    created = cc.create_commit(
        repositoryName=repo, branchName="main", commitMessage="two files",
        putFiles=[{"filePath": "one.txt", "fileContent": one},
                  {"filePath": "two.txt", "fileContent": two}])
    c1, tree1 = created["commitId"], created["treeId"]
    expected_tree1 = _tree_sha1([("100644", "one.txt", _blob_sha1(one)),
                                 ("100644", "two.txt", _blob_sha1(two))])
    assert tree1 == expected_tree1, (
        f"CreateCommit reported treeId {tree1!r}; the git root tree of those two payloads "
        f"is {expected_tree1!r}"
    )
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == c1, (
        "the branch did not advance to the first commit"
    )

    # Break exactly one thing: propose the identical tree again. Same parent, same paths,
    # byte-identical content -- the only difference from an accepted request is that the
    # bytes are already there.
    code, message = _error(lambda: cc.create_commit(
        repositoryName=repo, branchName="main", parentCommitId=c1,
        commitMessage="no effective change",
        putFiles=[{"filePath": "one.txt", "fileContent": one},
                  {"filePath": "two.txt", "fileContent": two}]))
    assert code == "NoChangeException", (
        f"CreateCommit reproducing the current tree raised {code!r}, expected "
        f"'NoChangeException'"
    )
    expected = (
        "Cannot create the commit. At least one change is required to create a commit, but the "
        "files in the commit are exactly the same as the files in the parent commit. If you "
        "want to create an empty commit, use a Git client."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no new commit, and the tree the tip points at is byte-for-byte the
    # one that was already there.
    tip = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert tip == c1, (
        f"main is at {tip!r} after the refused commit, expected the unchanged tip {c1!r}"
    )
    still = cc.get_commit(repositoryName=repo, commitId=c1)["commit"]
    assert still["treeId"] == tree1, (
        f"GetCommit({c1}) now reports treeId {still['treeId']!r}, expected the unchanged "
        f"{tree1!r}"
    )
    for path, content in (("one.txt", one), ("two.txt", two)):
        got = cc.get_file(repositoryName=repo, commitSpecifier="main", filePath=path)
        assert got["fileContent"] == content, (
            f"GetFile({path}) after the refusal returned {got['fileContent']!r}, expected "
            f"the unchanged {content!r}"
        )

    # PutFile of the identical bytes at an existing path is refused for the same reason
    # but under its OWN code: real AWS answers SameFileContentException there, not
    # NoChangeException. Pinning both is the point -- an emulator that collapses the two into
    # one code is wrong in a way a caller can see, because only NoChangeException is documented
    # for the multi-file request.
    put_code, put_message = _error(lambda: cc.put_file(
        repositoryName=repo, branchName="main", filePath="one.txt", fileContent=one,
        parentCommitId=c1, commitMessage="no effective change, single file"))
    assert put_code == "SameFileContentException", (
        f"PutFile rewriting a path with its current bytes raised {put_code!r}, expected "
        f"'SameFileContentException'"
    )
    put_expected = (
        "The content of the file is exactly the same as the content of the file in the AWS "
        "CodeCommit repository and branch you specified. The file has not been added."
    )
    assert put_message == put_expected, (
        f"expected message {put_expected!r}, got {put_message!r}"
    )
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == c1, (
        "the refused PutFile still advanced the branch"
    )

    # Positive control, same request shape, same parent: one byte differs and it lands.
    control = cc.create_commit(
        repositoryName=repo, branchName="main", parentCommitId=c1,
        commitMessage="one byte differs",
        putFiles=[{"filePath": "one.txt", "fileContent": one_changed},
                  {"filePath": "two.txt", "fileContent": two}])
    c2, tree2 = control["commitId"], control["treeId"]
    assert c2 != c1, f"the control commit reused the parent's id {c1!r}"
    expected_tree2 = _tree_sha1([("100644", "one.txt", _blob_sha1(one_changed)),
                                 ("100644", "two.txt", _blob_sha1(two))])
    assert tree2 == expected_tree2, (
        f"the control commit's treeId is {tree2!r}; the git root tree after the one-byte "
        f"change is {expected_tree2!r}"
    )
    assert tree2 != tree1, (
        f"the control commit's treeId {tree2!r} equals the pre-change tree {tree1!r}; a "
        f"one-byte change must produce a different tree"
    )
    assert cc.get_commit(repositoryName=repo, commitId=c2)["commit"]["parents"] == [c1], (
        f"the control commit's parents are "
        f"{cc.get_commit(repositoryName=repo, commitId=c2)['commit']['parents']!r}, "
        f"expected exactly [{c1!r}]"
    )
    landed = cc.get_file(repositoryName=repo, commitSpecifier=c2, filePath="one.txt")
    assert landed["fileContent"] == one_changed, (
        f"one.txt at the control commit is {landed['fileContent']!r}, expected "
        f"{one_changed!r}"
    )
    assert landed["blobId"] == _blob_sha1(one_changed), (
        f"one.txt at the control commit has blobId {landed['blobId']!r}; the git blob id "
        f"of the changed bytes is {_blob_sha1(one_changed)!r}"
    )


# ===== helpers =====

def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _blob_sha1(content: bytes) -> str:
    """Git blob object id: sha1 of b'blob <bytelen>' + NUL + raw content.

    Not a security hash -- git's object-id construction is defined as SHA-1.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 - git object id


def _tree_sha1(entries) -> str:
    """Git tree object id from (mode, name, hex_sha) triples, ordered by name."""
    body = b""
    for mode, name, sha in sorted(entries, key=lambda e: (e[1] + "/" if e[0] == "40000" else e[1]).encode("utf-8")):
        body += mode.encode("ascii") + b" " + name.encode("utf-8") + b"\x00" + binascii.unhexlify(sha)
    header = b"tree " + str(len(body)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + body).hexdigest()  # noqa: S324 - git object id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
