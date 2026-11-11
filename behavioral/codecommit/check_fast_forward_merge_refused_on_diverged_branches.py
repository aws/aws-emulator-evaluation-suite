"""fast-forward-merge-refused-on-diverged-branches."""
from __future__ import annotations

import binascii
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fast-forward-merge-refused-on-diverged-branches"
GROUP = 'overly-permissive'
SERVICES = ['codecommit']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Diverged branches drop FAST_FORWARD_MERGE from GetMergeOptions and a fast-forward is
    refused (ManualMergeRequiredException) leaving main untouched, so no commits are lost;
    a three-way merge of the same branches succeeds with the union tree.
    """
    cc = ctx.client("codecommit")
    meta = cc.create_repository(repositoryName=ctx.unique_name("sim2real-behav-repo-"))["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo = meta["repositoryName"]

    base = b"shared base\n"
    on_feature = b"added on the feature branch\n"
    on_main = b"added on main after the branch point\n"

    c_base = cc.put_file(
        repositoryName=repo, branchName="main", filePath="base.txt",
        fileContent=base, commitMessage="base",
    )["commitId"]

    feature = ctx.unique_name("sim2real-behav-branch-")
    cc.create_branch(repositoryName=repo, branchName=feature, commitId=c_base)

    c_feat = cc.put_file(
        repositoryName=repo, branchName=feature, filePath="feat.txt",
        fileContent=on_feature, parentCommitId=c_base, commitMessage="feature work",
    )["commitId"]

    # While main is still an ancestor of the feature branch, fast-forward is legal and
    # must be offered. This is the positive control for the option listing.
    ahead = cc.get_merge_options(
        repositoryName=repo, sourceCommitSpecifier=feature, destinationCommitSpecifier="main",
    )
    assert "FAST_FORWARD_MERGE" in ahead["mergeOptions"], (
        f"with main an ancestor of {feature}, GetMergeOptions omitted FAST_FORWARD_MERGE: "
        f"{ahead['mergeOptions']!r}"
    )
    assert ahead["baseCommitId"] == c_base, f"baseCommitId {ahead['baseCommitId']!r} != {c_base!r}"

    # Break exactly one thing: give main a commit of its own, so the two branches diverge.
    c_main = cc.put_file(
        repositoryName=repo, branchName="main", filePath="main.txt",
        fileContent=on_main, parentCommitId=c_base, commitMessage="parallel work on main",
    )["commitId"]
    assert c_main != c_feat, "setup failed to diverge the branches"

    diverged = cc.get_merge_options(
        repositoryName=repo, sourceCommitSpecifier=feature, destinationCommitSpecifier="main",
    )
    assert "FAST_FORWARD_MERGE" not in diverged["mergeOptions"], (
        f"GetMergeOptions still offers FAST_FORWARD_MERGE for diverged branches: "
        f"{diverged['mergeOptions']!r}"
    )
    assert {"SQUASH_MERGE", "THREE_WAY_MERGE"} <= set(diverged["mergeOptions"]), (
        f"GetMergeOptions dropped the legal strategies too: {diverged['mergeOptions']!r}"
    )
    assert diverged["baseCommitId"] == c_base, (
        f"merge base is {diverged['baseCommitId']!r}, expected the branch point {c_base!r}"
    )
    assert diverged["sourceCommitId"] == c_feat, f"sourceCommitId {diverged['sourceCommitId']!r}"
    assert diverged["destinationCommitId"] == c_main, f"destinationCommitId {diverged['destinationCommitId']!r}"

    try:
        cc.merge_branches_by_fast_forward(
            repositoryName=repo, sourceCommitSpecifier=feature,
            destinationCommitSpecifier="main", targetBranch="main",
        )
        raise AssertionError(
            f"fast-forward merge of diverged branches was accepted; main was at {c_main} "
            f"with its own commit, and fast-forwarding to {c_feat} discards it"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ManualMergeRequiredException", (
            f"fast-forward of diverged branches raised {code!r}, expected ManualMergeRequiredException"
        )
        message = exc.response["Error"].get("Message")
        assert message == (
            "Current branches cannot be merged, please try to merge using a Git client locally."
        ), message

    # Effect absent: main is untouched and has not acquired the feature branch's file.
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == c_main, (
        "the refused fast-forward moved the destination branch anyway"
    )
    try:
        cc.get_file(repositoryName=repo, commitSpecifier="main", filePath="feat.txt")
        raise AssertionError("feat.txt is reachable from main after the merge was refused")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "FileDoesNotExistException", f"GetFile feat.txt on main raised {code!r}"
        message = exc.response["Error"].get("Message")
        assert message == "Could not find path feat.txt", message
    assert cc.get_file(
        repositoryName=repo, commitSpecifier="main", filePath="main.txt"
    )["fileContent"] == on_main, "main's own commit was lost"

    # Control: the legal strategy on the identical pair of branches succeeds and keeps
    # both sides' work, in a commit with two parents.
    merged = cc.merge_branches_by_three_way(
        repositoryName=repo, sourceCommitSpecifier=feature,
        destinationCommitSpecifier="main", targetBranch="main",
        commitMessage="three-way merge", authorName="sim2real", email="sim2real@example.com",
    )
    assert merged["commitId"] not in (c_base, c_main, c_feat), (
        f"three-way merge reused an existing commit id {merged['commitId']!r}"
    )
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == merged["commitId"], (
        "main was not advanced to the merge commit"
    )

    expected_tree = _tree_sha1([
        ("100644", "base.txt", _blob_sha1(base)),
        ("100644", "feat.txt", _blob_sha1(on_feature)),
        ("100644", "main.txt", _blob_sha1(on_main)),
    ])
    assert merged["treeId"] == expected_tree, (
        f"merge commit treeId {merged['treeId']!r} != the union of both branches "
        f"{expected_tree!r} -- the merge dropped or duplicated a path"
    )

    commit = cc.get_commit(repositoryName=repo, commitId=merged["commitId"])["commit"]
    # parents[0] is the destination (main), parents[1] the source (feature) -- git's
    # first-parent convention, not just a set of two.
    assert len(commit["parents"]) == 2, (
        f"merge commit has {len(commit['parents'])} parents: {commit['parents']!r}, expected 2"
    )
    assert commit["parents"] == [c_main, c_feat], (
        f"merge commit parents {commit['parents']!r} != [{c_main!r}, {c_feat!r}] "
        "(destination first, per git's first-parent convention)"
    )
    assert cc.get_file(
        repositoryName=repo, commitSpecifier="main", filePath="feat.txt"
    )["blobId"] == _blob_sha1(on_feature), "the merge did not bring the feature file onto main"

    # The feature branch itself is not moved by merging it into main.
    assert cc.get_branch(repositoryName=repo, branchName=feature)["branch"]["commitId"] == c_feat, (
        "merging the source into the destination moved the source branch"
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
