"""delete-file-restores-prior-tree-id."""
from __future__ import annotations

import binascii
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-file-restores-prior-tree-id"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Adding then deleting a file returns the tree id to its earlier value (recomputed locally from the
    bytes) while the commit id is new, and GetCommit, GetFolder and GetFile agree."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"),
        tags={"sim2real": "delete-file-restores-prior-tree-id"},
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo = meta["repositoryName"]

    alpha = b"alpha\n"
    beta = b"beta\n"

    put1 = cc.put_file(
        repositoryName=repo, branchName="main", filePath="src/a.txt",
        fileContent=alpha, commitMessage="add a",
    )
    c1, tree1 = put1["commitId"], put1["treeId"]

    src1 = _tree_sha1([("100644", "a.txt", _blob_sha1(alpha))])
    root1 = _tree_sha1([("40000", "src", src1)])
    assert tree1 == root1, f"PutFile treeId {tree1!r} != computed root tree {root1!r}"

    put2 = cc.put_file(
        repositoryName=repo, branchName="main", filePath="src/b.txt",
        fileContent=beta, parentCommitId=c1, commitMessage="add b",
    )
    c2, tree2 = put2["commitId"], put2["treeId"]

    src2 = _tree_sha1([
        ("100644", "a.txt", _blob_sha1(alpha)),
        ("100644", "b.txt", _blob_sha1(beta)),
    ])
    root2 = _tree_sha1([("40000", "src", src2)])
    assert tree2 == root2, f"PutFile treeId {tree2!r} != computed root tree {root2!r}"
    assert root1 != root2, "test setup produced identical trees"

    deleted = cc.delete_file(
        repositoryName=repo, branchName="main", filePath="src/b.txt",
        parentCommitId=c2, commitMessage="drop b",
    )
    c3 = deleted["commitId"]

    assert deleted["treeId"] == root1, (
        f"after deleting the only added file the tree id is {deleted['treeId']!r}; "
        f"it must return to the pre-add tree {root1!r}"
    )
    assert deleted["blobId"] == _blob_sha1(beta), (
        f"DeleteFile reported blobId {deleted['blobId']!r} for the removed file, "
        f"expected the deleted content's id {_blob_sha1(beta)!r}"
    )
    assert deleted["filePath"] == "src/b.txt", f"DeleteFile echoed {deleted['filePath']!r}"

    # Same tree, new commit: history advances even though content reverted.
    assert c3 != c1, f"delete reused the earlier commit id {c1!r}"
    commit3 = cc.get_commit(repositoryName=repo, commitId=c3)["commit"]
    assert commit3["treeId"] == root1, f"GetCommit({c3}) treeId {commit3['treeId']!r} != {root1!r}"
    assert commit3["parents"] == [c2], (
        f"GetCommit({c3}) parents {commit3['parents']!r}, expected exactly [{c2!r}]"
    )
    commit1 = cc.get_commit(repositoryName=repo, commitId=c1)["commit"]
    assert commit1["treeId"] == root1, f"GetCommit({c1}) treeId {commit1['treeId']!r} != {root1!r}"
    # The root commit has no parents. `parents` is not a required member, so an absent
    # key and an empty list are both "no parents"; anything else is wrong.
    assert commit1.get("parents", []) == [], (
        f"the initial commit reports parents {commit1.get('parents')!r}, expected none"
    )

    # The surviving sibling is untouched, the deleted path is gone, and the surviving
    # folder's own subtree id matches the recomputed subtree.
    survivor = cc.get_file(repositoryName=repo, commitSpecifier="main", filePath="src/a.txt")
    assert survivor["fileContent"] == alpha, f"src/a.txt content changed: {survivor['fileContent']!r}"
    assert survivor["blobId"] == _blob_sha1(alpha), f"src/a.txt blobId {survivor['blobId']!r}"

    folder = cc.get_folder(repositoryName=repo, commitSpecifier="main", folderPath="src")
    assert folder["treeId"] == src1, f"GetFolder('src') treeId {folder['treeId']!r} != {src1!r}"
    assert [f["absolutePath"] for f in folder["files"]] == ["src/a.txt"], (
        f"GetFolder('src') files {[f['absolutePath'] for f in folder['files']]!r}"
    )

    try:
        cc.get_file(repositoryName=repo, commitSpecifier="main", filePath="src/b.txt")
        raise AssertionError("GetFile still resolves the deleted path src/b.txt at the branch tip")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "FileDoesNotExistException", f"GetFile on deleted path raised {code!r}"
        expected = "Could not find path src/b.txt"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # History is not rewritten: the deleted content is still reachable at c2.
    at_c2 = cc.get_file(repositoryName=repo, commitSpecifier=c2, filePath="src/b.txt")
    assert at_c2["fileContent"] == beta, (
        f"deleting from the tip changed the historical commit {c2}: {at_c2['fileContent']!r}"
    )

    # The dead path is not just unreadable, it is unusable: a second DeleteFile against
    # the now-current tip must fail the same way GetFile did, not silently no-op.
    try:
        cc.delete_file(
            repositoryName=repo, branchName="main", filePath="src/b.txt",
            parentCommitId=c3, commitMessage="drop b again",
        )
        raise AssertionError("DeleteFile succeeded again on a path already removed from the tip")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "FileDoesNotExistException", (
            f"repeat DeleteFile on the already-removed path raised {code!r}, expected "
            f"FileDoesNotExistException"
        )
        expected = "Cannot find the specified file."
        assert message == expected, f"expected message {expected!r}, got {message!r}"


def _blob_sha1(content: bytes) -> str:
    """Git blob object id: sha1 of b'blob <bytelen>' + NUL + raw content.

    Not a security hash -- git's object-id construction is defined as SHA-1.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 - git object id


def _tree_sha1(entries) -> str:
    """Git tree object id from (mode, name, hex_sha) triples.

    Body is the concatenation of mode + ' ' + name + NUL + 20 raw sha bytes, with entries ordered by
    name -- and, per git's base_name_compare, a subtree sorts as if its name carried a trailing '/'.
    """
    body = b""
    for mode, name, sha in sorted(entries, key=lambda e: (e[1] + "/" if e[0] == "40000" else e[1]).encode("utf-8")):
        body += mode.encode("ascii") + b" " + name.encode("utf-8") + b"\x00" + binascii.unhexlify(sha)
    header = b"tree " + str(len(body)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + body).hexdigest()  # noqa: S324 - git object id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
