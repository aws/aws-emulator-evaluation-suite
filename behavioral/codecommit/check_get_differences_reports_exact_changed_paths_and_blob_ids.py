"""get-differences-reports-exact-changed-paths-and-blob-ids."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "get-differences-reports-exact-changed-paths-and-blob-ids"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetDifferences reports only the changed paths with change types A/M/D, mode 100644 and the blob
    ids of both versions (recomputed locally); swapping the commits inverts the diff, and a commit
    against itself has none."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "ccgdiff"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo = meta["repositoryName"]

    keep = b"unchanged\n"
    before_mod = b"version one\n"
    after_mod = b"version two -- longer\n"
    gone = b"about to be removed\n"
    added = b"brand new\n"

    c1 = cc.create_commit(
        repositoryName=repo, branchName="main", commitMessage="baseline",
        putFiles=[
            {"filePath": "keep.txt", "fileMode": "NORMAL", "fileContent": keep},
            {"filePath": "mod.txt", "fileMode": "NORMAL", "fileContent": before_mod},
            {"filePath": "gone.txt", "fileMode": "NORMAL", "fileContent": gone},
        ],
    )["commitId"]

    c2 = cc.create_commit(
        repositoryName=repo, branchName="main", parentCommitId=c1,
        commitMessage="modify one, add one, delete one, leave one alone",
        putFiles=[
            {"filePath": "mod.txt", "fileMode": "NORMAL", "fileContent": after_mod},
            {"filePath": "add.txt", "fileMode": "NORMAL", "fileContent": added},
        ],
        deleteFiles=[{"filePath": "gone.txt"}],
    )["commitId"]

    forward = _diff_by_path(cc, repo, c1, c2)
    assert sorted(forward) == ["add.txt", "gone.txt", "mod.txt"], (
        f"GetDifferences({c1[:8]}..{c2[:8]}) reported paths {sorted(forward)}; "
        "expected exactly the three changed paths, with keep.txt absent"
    )

    add_d = forward["add.txt"]
    assert add_d["changeType"] == "A", f"add.txt changeType {add_d['changeType']!r}, expected 'A'"
    assert "beforeBlob" not in add_d, f"an added path carries a beforeBlob: {add_d.get('beforeBlob')!r}"
    assert add_d["afterBlob"]["blobId"] == _blob_sha1(added), (
        f"add.txt afterBlob.blobId {add_d['afterBlob']['blobId']!r} != {_blob_sha1(added)!r}"
    )
    assert add_d["afterBlob"]["mode"] == "100644", (
        f"add.txt afterBlob.mode {add_d['afterBlob']['mode']!r}, expected the git mode '100644'"
    )
    assert add_d["afterBlob"]["path"] == "add.txt", f"add.txt afterBlob.path {add_d['afterBlob']['path']!r}"

    mod_d = forward["mod.txt"]
    assert mod_d["changeType"] == "M", f"mod.txt changeType {mod_d['changeType']!r}, expected 'M'"
    assert mod_d["beforeBlob"]["blobId"] == _blob_sha1(before_mod), (
        f"mod.txt beforeBlob.blobId {mod_d['beforeBlob']['blobId']!r} != {_blob_sha1(before_mod)!r}"
    )
    assert mod_d["afterBlob"]["blobId"] == _blob_sha1(after_mod), (
        f"mod.txt afterBlob.blobId {mod_d['afterBlob']['blobId']!r} != {_blob_sha1(after_mod)!r}"
    )
    assert mod_d["beforeBlob"]["blobId"] != mod_d["afterBlob"]["blobId"], (
        "a modified path reported the same blob id before and after"
    )

    gone_d = forward["gone.txt"]
    assert gone_d["changeType"] == "D", f"gone.txt changeType {gone_d['changeType']!r}, expected 'D'"
    assert "afterBlob" not in gone_d, f"a deleted path carries an afterBlob: {gone_d.get('afterBlob')!r}"
    assert gone_d["beforeBlob"]["blobId"] == _blob_sha1(gone), (
        f"gone.txt beforeBlob.blobId {gone_d['beforeBlob']['blobId']!r} != {_blob_sha1(gone)!r}"
    )

    # Reversing the specifiers inverts the diff: A becomes D, D becomes A, and M swaps
    # its two blob ids. An emulator that diffs against the empty tree cannot do this.
    reverse = _diff_by_path(cc, repo, c2, c1)
    assert sorted(reverse) == ["add.txt", "gone.txt", "mod.txt"], (
        f"reversed GetDifferences reported paths {sorted(reverse)}"
    )
    assert reverse["add.txt"]["changeType"] == "D", (
        f"reversed, add.txt is {reverse['add.txt']['changeType']!r}, expected 'D'"
    )
    assert reverse["gone.txt"]["changeType"] == "A", (
        f"reversed, gone.txt is {reverse['gone.txt']['changeType']!r}, expected 'A'"
    )
    assert reverse["mod.txt"]["beforeBlob"]["blobId"] == _blob_sha1(after_mod), (
        f"reversed mod.txt beforeBlob {reverse['mod.txt']['beforeBlob']['blobId']!r} "
        f"!= {_blob_sha1(after_mod)!r}"
    )
    assert reverse["mod.txt"]["afterBlob"]["blobId"] == _blob_sha1(before_mod), (
        f"reversed mod.txt afterBlob {reverse['mod.txt']['afterBlob']['blobId']!r} "
        f"!= {_blob_sha1(before_mod)!r}"
    )

    # A commit against itself has no differences at all.
    assert _diff_by_path(cc, repo, c2, c2) == {}, (
        "GetDifferences of a commit against itself reported changes"
    )


def _diff_by_path(cc, repo, before, after):
    """All differences between two commits, keyed by path (paths are unique per diff).

    Paginated with the operation's own NextToken rather than a page-1 read, so a
    diff wider than one page is not silently truncated. Keying by path makes the
    assertions independent of an undocumented result order while keeping the set of
    paths and every per-path field exact.
    """
    out = {}
    token = None
    while True:
        kwargs = {"repositoryName": repo, "beforeCommitSpecifier": before, "afterCommitSpecifier": after}
        if token:
            kwargs["NextToken"] = token
        page = cc.get_differences(**kwargs)
        for d in page.get("differences", []):
            blob = d.get("afterBlob") or d.get("beforeBlob")
            assert blob and blob.get("path"), f"difference entry carries no path: {d!r}"
            out[blob["path"]] = d
        token = page.get("NextToken")
        if not token:
            return out


def _blob_sha1(content: bytes) -> str:
    """Git blob object id: sha1 of b'blob <bytelen>' + NUL + raw content.

    Not a security hash -- git's object-id construction is defined as SHA-1.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 - git object id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
