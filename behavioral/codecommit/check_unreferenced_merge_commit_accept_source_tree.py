"""unreferenced-merge-commit-accept-source-tree."""
from __future__ import annotations

import binascii
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unreferenced-merge-commit-accept-source-tree"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A content conflict is reported with exact per-side metadata, an unresolved three-way
    merge is refused, and CreateUnreferencedMergeCommit with ACCEPT_SOURCE yields exactly
    the source tree, reachable by commit id but on no branch.
    """
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "ccumc"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo = meta["repositoryName"]

    base_txt = b"the original line\n"
    left_txt = b"the line as rewritten on the left branch\n"
    right_txt = b"the line as rewritten on the right\n"
    assert len({len(base_txt), len(left_txt), len(right_txt)}) == 3, "sizes must differ to be diagnostic"

    c_base = cc.put_file(
        repositoryName=repo, branchName="main", filePath="conflict.txt",
        fileContent=base_txt, commitMessage="base",
    )["commitId"]

    left = ctx.unique_name("sim2real-behav-branch-")
    right = ctx.unique_name("sim2real-behav-branch-")
    cc.create_branch(repositoryName=repo, branchName=left, commitId=c_base)
    cc.create_branch(repositoryName=repo, branchName=right, commitId=c_base)

    c_left = cc.put_file(
        repositoryName=repo, branchName=left, filePath="conflict.txt",
        fileContent=left_txt, parentCommitId=c_base, commitMessage="left edit",
    )["commitId"]
    c_right = cc.put_file(
        repositoryName=repo, branchName=right, filePath="conflict.txt",
        fileContent=right_txt, parentCommitId=c_base, commitMessage="right edit",
    )["commitId"]

    conflicts = cc.get_merge_conflicts(
        repositoryName=repo, destinationCommitSpecifier=left, sourceCommitSpecifier=right,
        mergeOption="THREE_WAY_MERGE", conflictDetailLevel="FILE_LEVEL",
    )
    assert conflicts["mergeable"] is False, (
        f"GetMergeConflicts reported mergeable={conflicts['mergeable']!r} for two edits "
        "of the same line from a common base"
    )
    assert conflicts["baseCommitId"] == c_base, f"baseCommitId {conflicts['baseCommitId']!r} != {c_base!r}"
    assert conflicts["destinationCommitId"] == c_left, f"destinationCommitId {conflicts['destinationCommitId']!r}"
    assert conflicts["sourceCommitId"] == c_right, f"sourceCommitId {conflicts['sourceCommitId']!r}"

    metas = {m["filePath"]: m for m in conflicts["conflictMetadataList"]}
    assert sorted(metas) == ["conflict.txt"], (
        f"conflictMetadataList covers {sorted(metas)}, expected exactly the one conflicting path"
    )
    cm = metas["conflict.txt"]
    assert cm["contentConflict"] is True, f"contentConflict {cm['contentConflict']!r}"
    assert cm["fileModeConflict"] is False, f"fileModeConflict {cm['fileModeConflict']!r} (both sides are NORMAL)"
    assert cm["objectTypeConflict"] is False, f"objectTypeConflict {cm['objectTypeConflict']!r} (both sides are files)"
    assert cm["numberOfConflicts"] == 1, f"numberOfConflicts {cm['numberOfConflicts']!r}, expected 1"
    assert cm["fileSizes"] == {
        "base": len(base_txt), "destination": len(left_txt), "source": len(right_txt),
    }, f"fileSizes {cm['fileSizes']!r} != the three actual byte lengths"
    assert cm["fileModes"] == {"base": "NORMAL", "destination": "NORMAL", "source": "NORMAL"}, (
        f"fileModes {cm['fileModes']!r}"
    )
    assert cm["objectTypes"] == {"base": "FILE", "destination": "FILE", "source": "FILE"}, (
        f"objectTypes {cm['objectTypes']!r}"
    )
    assert cm["mergeOperations"] == {"source": "M", "destination": "M"}, (
        f"mergeOperations {cm['mergeOperations']!r}, expected both sides modified"
    )
    assert cm["isBinaryFile"] == {"base": False, "destination": False, "source": False}, (
        f"isBinaryFile {cm['isBinaryFile']!r}"
    )

    # Positive control: a non-conflicting three-way merge succeeds and advances its
    # target branch. Without this, the refusal below cannot be told apart from a target
    # that raises ManualMergeRequiredException for every THREE_WAY_MERGE call.
    control = ctx.unique_name("sim2real-behav-branch-")
    cc.create_branch(repositoryName=repo, branchName=control, commitId=c_base)
    cc.put_file(
        repositoryName=repo, branchName=control, filePath="unrelated.txt",
        fileContent=b"a file neither conflicting branch ever touches\n",
        parentCommitId=c_base, commitMessage="control edit",
    )
    control_merge = cc.merge_branches_by_three_way(
        repositoryName=repo, sourceCommitSpecifier=control, destinationCommitSpecifier="main",
        targetBranch="main", commitMessage="positive control: non-conflicting three-way merge",
        authorName="sim2real", email="sim2real@example.com",
    )
    c_main = control_merge.get("commitId")
    assert c_main, f"positive-control merge returned no commitId: {control_merge!r}"
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == c_main, (
        "positive-control merge succeeded but main did not advance to the merge commit"
    )

    # Unresolved: refused, and the destination branch does not move.
    try:
        cc.merge_branches_by_three_way(
            repositoryName=repo, sourceCommitSpecifier=right,
            destinationCommitSpecifier=left, targetBranch=left,
            commitMessage="merge without resolving the conflict",
            authorName="sim2real", email="sim2real@example.com",
        )
        raise AssertionError(
            "a three-way merge with an unresolved content conflict was accepted; the "
            "conflicting content was silently discarded"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ManualMergeRequiredException", (
            f"unresolved conflicting merge raised {code!r}, expected ManualMergeRequiredException"
        )
        expected_message = (
            "Current branches cannot be merged, please try to merge using a Git client locally."
        )
        assert message == expected_message, (
            f"unresolved conflicting merge raised message {message!r}, expected {expected_message!r}"
        )
    assert cc.get_branch(repositoryName=repo, branchName=left)["branch"]["commitId"] == c_left, (
        "the refused merge advanced the destination branch"
    )
    assert cc.get_file(
        repositoryName=repo, commitSpecifier=left, filePath="conflict.txt"
    )["fileContent"] == left_txt, "the refused merge changed the destination branch's content"

    # Same call, one input changed: resolve by taking the source side.
    unref = cc.create_unreferenced_merge_commit(
        repositoryName=repo, sourceCommitSpecifier=right, destinationCommitSpecifier=left,
        mergeOption="THREE_WAY_MERGE", conflictDetailLevel="FILE_LEVEL",
        conflictResolutionStrategy="ACCEPT_SOURCE",
        commitMessage="resolved by accepting the source",
        authorName="sim2real", email="sim2real@example.com",
    )
    u_commit, u_tree = unref["commitId"], unref["treeId"]

    source_tree = _tree_sha1([("100644", "conflict.txt", _blob_sha1(right_txt))])
    assert u_tree == source_tree, (
        f"ACCEPT_SOURCE produced treeId {u_tree!r}; it must be the source commit's tree "
        f"verbatim, {source_tree!r}"
    )
    assert u_tree != _tree_sha1([("100644", "conflict.txt", _blob_sha1(left_txt))]), (
        "ACCEPT_SOURCE produced the destination tree"
    )

    # It is a real object, with both sides as parents...
    commit = cc.get_commit(repositoryName=repo, commitId=u_commit)["commit"]
    assert commit["treeId"] == u_tree, f"GetCommit treeId {commit['treeId']!r} != {u_tree!r}"
    assert len(commit["parents"]) == 2, f"unreferenced merge commit parents {commit['parents']!r}, expected 2"
    assert set(commit["parents"]) == {c_left, c_right}, (
        f"unreferenced merge commit parents {commit['parents']!r} != {{{c_left!r}, {c_right!r}}}"
    )
    assert cc.get_file(
        repositoryName=repo, commitSpecifier=u_commit, filePath="conflict.txt"
    )["fileContent"] == right_txt, "the unreferenced commit's content is not the source content"

    # ...and it is retrievable as the merge result for that exact strategy.
    got = cc.get_merge_commit(
        repositoryName=repo, sourceCommitSpecifier=right, destinationCommitSpecifier=left,
        conflictDetailLevel="FILE_LEVEL", conflictResolutionStrategy="ACCEPT_SOURCE",
    )
    assert got["mergedCommitId"] == u_commit, (
        f"GetMergeCommit returned mergedCommitId {got.get('mergedCommitId')!r}, expected {u_commit!r}"
    )
    assert got["baseCommitId"] == c_base, f"GetMergeCommit baseCommitId {got.get('baseCommitId')!r}"

    # Unreferenced means unreferenced: no branch points at it, and the two branches are
    # exactly where they were.
    tips = {}
    for branch in cc.list_branches(repositoryName=repo)["branches"]:
        tips[branch] = cc.get_branch(repositoryName=repo, branchName=branch)["branch"]["commitId"]
    assert u_commit not in set(tips.values()), (
        f"the unreferenced merge commit {u_commit} is the tip of a branch: "
        f"{[b for b, t in tips.items() if t == u_commit]!r}"
    )
    assert tips[left] == c_left, f"branch {left} moved to {tips[left]!r}, expected {c_left!r}"
    assert tips[right] == c_right, f"branch {right} moved to {tips[right]!r}, expected {c_right!r}"
    assert tips["main"] == c_main, (
        f"branch main moved to {tips['main']!r}, expected {c_main!r} (its tip after the "
        "positive-control merge, unaffected by the unreferenced merge commit)"
    )


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
