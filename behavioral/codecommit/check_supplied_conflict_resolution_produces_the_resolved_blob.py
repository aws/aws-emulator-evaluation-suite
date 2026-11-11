"""supplied-conflict-resolution-produces-the-resolved-blob."""
from __future__ import annotations

import binascii
import hashlib

from behavioral_harness import tags

CHECK = "supplied-conflict-resolution-produces-the-resolved-blob"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A USE_NEW_CONTENT conflict resolution in MergeBranchesByThreeWay yields a merge
    commit whose conflicted file is exactly the supplied bytes at their git blob id, with
    every unrelated path left at its own blob."""
    cc = ctx.client("codecommit")

    repo = ctx.unique_name("sim2real-behav-ccres-")
    cc.create_repository(repositoryName=repo, tags={"sim2real": "ccres"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    untouched = b"this line belongs to neither branch\n"
    base_line = b"original\n"
    from_a = b"rewritten by feat-a\n"
    from_b = b"rewritten by feat-b\n"
    resolved = b"neither side won; the caller supplied this\n"

    c0 = cc.put_file(repositoryName=repo, branchName="main", filePath="untouched.txt",
                     fileContent=untouched, commitMessage="untouched")["commitId"]
    base = cc.put_file(repositoryName=repo, branchName="main", filePath="conflict.txt",
                       fileContent=base_line, parentCommitId=c0,
                       commitMessage="conflict base")["commitId"]
    untouched_blob = cc.get_file(repositoryName=repo, commitSpecifier=base,
                                 filePath="untouched.txt")["blobId"]
    assert untouched_blob == _blob_sha1(untouched), (
        f"untouched.txt blobId on main is {untouched_blob!r}, the git blob id of those "
        f"bytes is {_blob_sha1(untouched)!r}"
    )

    cc.create_branch(repositoryName=repo, branchName="feat-a", commitId=base)
    cc.create_branch(repositoryName=repo, branchName="feat-b", commitId=base)
    head_a = cc.put_file(repositoryName=repo, branchName="feat-a", filePath="conflict.txt",
                         fileContent=from_a, parentCommitId=base,
                         commitMessage="feat-a rewrite")["commitId"]
    head_b = cc.put_file(repositoryName=repo, branchName="feat-b", filePath="conflict.txt",
                         fileContent=from_b, parentCommitId=base,
                         commitMessage="feat-b rewrite")["commitId"]

    # The conflict really exists, and only on the one path -- otherwise the resolution
    # below would be resolving nothing.
    conflicts = cc.get_merge_conflicts(
        repositoryName=repo, sourceCommitSpecifier="feat-a",
        destinationCommitSpecifier="feat-b", mergeOption="THREE_WAY_MERGE")
    assert conflicts["mergeable"] is False, (
        f"GetMergeConflicts reports mergeable={conflicts['mergeable']!r} for two branches "
        f"that rewrote the same line of conflict.txt"
    )
    assert conflicts["baseCommitId"] == base, (
        f"the merge base is {conflicts['baseCommitId']!r}, expected {base!r}"
    )
    conflicting = [c["filePath"] for c in conflicts["conflictMetadataList"]]
    assert conflicting == ["conflict.txt"], (
        f"GetMergeConflicts lists {conflicting!r} as conflicting; only conflict.txt was "
        f"rewritten on both sides"
    )

    # Break nothing -- resolve it. AUTOMERGE is required alongside a supplied resolution:
    # real AWS refuses the pair with InvalidConflictResolutionException under the default
    # NONE strategy.
    merge = cc.merge_branches_by_three_way(
        repositoryName=repo, sourceCommitSpecifier="feat-a",
        destinationCommitSpecifier="feat-b", targetBranch="feat-b",
        conflictResolutionStrategy="AUTOMERGE",
        conflictResolution={"replaceContents": [{
            "filePath": "conflict.txt",
            "replacementType": "USE_NEW_CONTENT",
            "content": resolved,
        }]},
        commitMessage="merge with a supplied resolution")
    merge_commit = merge["commitId"]

    got = cc.get_file(repositoryName=repo, commitSpecifier=merge_commit,
                      filePath="conflict.txt")
    assert got["fileContent"] == resolved, (
        f"the merged conflict.txt is {len(got['fileContent'])} bytes "
        f"{got['fileContent']!r}; the supplied resolution was {len(resolved)} bytes "
        f"{resolved!r}"
    )
    assert got["blobId"] == _blob_sha1(resolved), (
        f"the merged conflict.txt blobId is {got['blobId']!r}; the git blob id of the "
        f"supplied bytes is {_blob_sha1(resolved)!r} -- the resolution must be stored as "
        f"a content-addressed object, not under a minted id"
    )
    assert got["fileContent"] not in (from_a, from_b, base_line), (
        f"the merged file is one of the three pre-existing versions {got['fileContent']!r}; "
        f"the supplied resolution was ignored"
    )

    # The resolution did not rewrite anything it was not asked to.
    kept = cc.get_file(repositoryName=repo, commitSpecifier=merge_commit,
                       filePath="untouched.txt")
    assert kept["blobId"] == untouched_blob, (
        f"untouched.txt is at blobId {kept['blobId']!r} in the merge commit but "
        f"{untouched_blob!r} on main -- the resolution rewrote an unrelated path"
    )
    assert kept["fileContent"] == untouched, (
        f"untouched.txt content changed to {kept['fileContent']!r} across the merge"
    )

    # A merge commit has both tips as parents, destination first (observed against real
    # AWS), and the destination ref now points at it.
    commit = cc.get_commit(repositoryName=repo, commitId=merge_commit)["commit"]
    assert commit["parents"] == [head_b, head_a], (
        f"the merge commit's parents are {commit['parents']!r}, expected exactly "
        f"[{head_b!r}, {head_a!r}] -- destination then source"
    )
    assert cc.get_branch(repositoryName=repo, branchName="feat-b")["branch"]["commitId"] \
        == merge_commit, (
        f"feat-b is at "
        f"{cc.get_branch(repositoryName=repo, branchName='feat-b')['branch']['commitId']!r}, "
        f"expected the merge commit {merge_commit!r}"
    )
    assert cc.get_branch(repositoryName=repo, branchName="feat-a")["branch"]["commitId"] \
        == head_a, "the source branch moved; only the target branch may advance"

    # The whole root tree is reproducible from the two blobs the merge should contain.
    expected_root = _tree_sha1([
        ("100644", "conflict.txt", _blob_sha1(resolved)),
        ("100644", "untouched.txt", _blob_sha1(untouched)),
    ])
    assert commit["treeId"] == expected_root, (
        f"the merge commit's treeId is {commit['treeId']!r}; a root tree holding the "
        f"resolved conflict.txt and the untouched untouched.txt is {expected_root!r}"
    )


# ===== helpers =====

def _blob_sha1(content: bytes) -> str:
    """Git blob object id: sha1 of b'blob <bytelen>' + NUL + raw content.

    Not a security hash -- git's object-id construction is defined as SHA-1.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 - git object id


def _tree_sha1(entries) -> str:
    """Git tree object id from (mode, name, hex_sha) triples.

    Body is mode + ' ' + name + NUL + 20 raw sha bytes per entry, entries ordered by
    name, and per git's base_name_compare a subtree sorts as if its name carried a
    trailing '/'.
    """
    body = b""
    for mode, name, sha in sorted(entries, key=lambda e: (e[1] + "/" if e[0] == "40000" else e[1]).encode("utf-8")):
        body += mode.encode("ascii") + b" " + name.encode("utf-8") + b"\x00" + binascii.unhexlify(sha)
    header = b"tree " + str(len(body)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + body).hexdigest()  # noqa: S324 - git object id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
