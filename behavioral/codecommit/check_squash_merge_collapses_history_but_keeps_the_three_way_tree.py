"""squash-merge-collapses-history-but-keeps-the-three-way-tree."""
from __future__ import annotations

import binascii
import hashlib

from behavioral_harness import tags

CHECK = "squash-merge-collapses-history-but-keeps-the-three-way-tree"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """MergeBranchesBySquash and a three-way merge of the same branches produce the same tree
    (also recomputed locally) but different history: one parent instead of two.
    """
    cc = ctx.client("codecommit")

    repo = ctx.unique_name("sim2real-behav-ccsq-")
    cc.create_repository(repositoryName=repo, tags={"sim2real": "ccsq"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    base_body = b"shared by both branches\n"
    a_body = b"only on feat-a\n"
    b_body = b"only on feat-b\n"

    base = cc.put_file(repositoryName=repo, branchName="main", filePath="base.txt",
                       fileContent=base_body, commitMessage="base")["commitId"]
    cc.create_branch(repositoryName=repo, branchName="feat-a", commitId=base)
    cc.create_branch(repositoryName=repo, branchName="feat-b", commitId=base)
    # Different files, so the merge is clean and the only thing under test is the
    # strategy's effect on history versus content.
    head_a = cc.put_file(repositoryName=repo, branchName="feat-a", filePath="a.txt",
                         fileContent=a_body, parentCommitId=base,
                         commitMessage="add a")["commitId"]
    head_b = cc.put_file(repositoryName=repo, branchName="feat-b", filePath="b.txt",
                         fileContent=b_body, parentCommitId=base,
                         commitMessage="add b")["commitId"]

    # A three-way merge that moves no ref at all: this is the reference tree.
    unreferenced = cc.create_unreferenced_merge_commit(
        repositoryName=repo, sourceCommitSpecifier="feat-a",
        destinationCommitSpecifier="feat-b", mergeOption="THREE_WAY_MERGE",
        commitMessage="three-way, unreferenced")
    three_way_tree = unreferenced["treeId"]
    assert cc.get_branch(repositoryName=repo, branchName="feat-b")["branch"]["commitId"] \
        == head_b, (
        "CreateUnreferencedMergeCommit advanced feat-b; it must move no ref"
    )
    assert cc.get_branch(repositoryName=repo, branchName="feat-a")["branch"]["commitId"] \
        == head_a, (
        "CreateUnreferencedMergeCommit advanced feat-a; it must move no ref"
    )

    squash = cc.merge_branches_by_squash(
        repositoryName=repo, sourceCommitSpecifier="feat-a",
        destinationCommitSpecifier="feat-b", targetBranch="feat-b",
        commitMessage="squash feat-a into feat-b")
    squash_commit = cc.get_commit(repositoryName=repo,
                                  commitId=squash["commitId"])["commit"]

    # Different history: one parent, the destination's pre-merge tip.
    assert squash_commit["parents"] == [head_b], (
        f"the squash commit's parents are {squash_commit['parents']!r}; a squash must have "
        f"exactly one parent, the destination tip {head_b!r} -- two parents means it was "
        f"performed as an ordinary merge"
    )

    # Same content: the tree the three-way merge computed, unchanged.
    assert squash_commit["treeId"] == three_way_tree, (
        f"the squash commit's treeId is {squash_commit['treeId']!r} but the three-way merge "
        f"of the same two branches produced {three_way_tree!r} -- the strategies differ in "
        f"history, never in content"
    )
    expected_tree = _tree_sha1([
        ("100644", "a.txt", _blob_sha1(a_body)),
        ("100644", "b.txt", _blob_sha1(b_body)),
        ("100644", "base.txt", _blob_sha1(base_body)),
    ])
    assert squash_commit["treeId"] == expected_tree, (
        f"the squash commit's treeId is {squash_commit['treeId']!r}; a root tree holding "
        f"all three payloads is {expected_tree!r}"
    )

    folder = cc.get_folder(repositoryName=repo, commitSpecifier=squash["commitId"],
                           folderPath="/")
    assert sorted(f["absolutePath"] for f in folder["files"]) == \
        ["a.txt", "b.txt", "base.txt"], (
        f"GetFolder at the squash commit lists "
        f"{sorted(f['absolutePath'] for f in folder['files'])!r}; both branches' files "
        f"plus the base must be present"
    )
    for path, content in (("a.txt", a_body), ("b.txt", b_body), ("base.txt", base_body)):
        got = cc.get_file(repositoryName=repo, commitSpecifier=squash["commitId"],
                          filePath=path)
        assert got["fileContent"] == content, (
            f"GetFile({path}) at the squash commit returned {got['fileContent']!r}, "
            f"expected {content!r}"
        )

    # Only the destination moved, and it moved to the squash commit.
    assert cc.get_branch(repositoryName=repo, branchName="feat-b")["branch"]["commitId"] \
        == squash["commitId"], (
        f"feat-b is at "
        f"{cc.get_branch(repositoryName=repo, branchName='feat-b')['branch']['commitId']!r}, "
        f"expected the squash commit {squash['commitId']!r}"
    )
    assert cc.get_branch(repositoryName=repo, branchName="feat-a")["branch"]["commitId"] \
        == head_a, (
        f"feat-a is at "
        f"{cc.get_branch(repositoryName=repo, branchName='feat-a')['branch']['commitId']!r}, "
        f"expected {head_a!r} -- a squash merges into the destination only"
    )

    # The source's individual commit is not reachable from the squash commit: that is what
    # "collapses history" means, and it is the half an emulator implementing squash as an
    # ordinary merge would get wrong. CodeCommit has no history operation, so walk the
    # parent chain with GetCommit -- the chain is base -> head_b -> squash, so three hops
    # is the whole graph and the bound is not a timeout in disguise.
    reachable, frontier = [], [squash["commitId"]]
    for _ in range(4):
        if not frontier:
            break
        nxt = []
        for cid in frontier:
            reachable.append(cid)
            nxt += cc.get_commit(repositoryName=repo, commitId=cid)["commit"].get("parents", [])
        frontier = nxt
    assert frontier == [], (
        f"the squash commit's ancestry is deeper than the three commits that exist; "
        f"still walking {frontier!r} after reaching {reachable!r}"
    )
    assert reachable == [squash["commitId"], head_b, base], (
        f"the squash commit's ancestry is {reachable!r}; a squash must produce exactly "
        f"[squash, {head_b!r}, {base!r}] and never import the source tip {head_a!r}"
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
