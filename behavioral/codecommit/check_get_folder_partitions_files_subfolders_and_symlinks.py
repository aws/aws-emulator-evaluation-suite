"""get-folder-partitions-files-subfolders-and-symlinks."""
from __future__ import annotations

import binascii
import hashlib

from behavioral_harness import tags

CHECK = "get-folder-partitions-files-subfolders-and-symlinks"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetFolder partitions one directory's entries into files / symbolicLinks / subFolders
    by object type, with EXECUTABLE and SYMLINK modes on the right entries, and each
    subFolder's treeId is the git tree id of that subtree."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "ccgfp"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo = meta["repositoryName"]

    plain = b"alpha\n"
    script = b"#!/bin/sh\necho hi\n"
    link_target = b"a.txt"
    nested = b"beta\n"

    created = cc.create_commit(
        repositoryName=repo, branchName="main",
        commitMessage="one directory holding a file, an executable, a symlink and a subfolder",
        putFiles=[
            {"filePath": "src/a.txt", "fileMode": "NORMAL", "fileContent": plain},
            {"filePath": "src/run.sh", "fileMode": "EXECUTABLE", "fileContent": script},
            {"filePath": "src/link.txt", "fileMode": "SYMLINK", "fileContent": link_target},
            {"filePath": "src/nested/b.txt", "fileMode": "NORMAL", "fileContent": nested},
        ],
    )
    commit_id, root_tree = created["commitId"], created["treeId"]

    nested_tree = _tree_sha1([("100644", "b.txt", _blob_sha1(nested))])
    src_tree = _tree_sha1([
        ("100644", "a.txt", _blob_sha1(plain)),
        ("100755", "run.sh", _blob_sha1(script)),
        ("120000", "link.txt", _blob_sha1(link_target)),
        ("40000", "nested", nested_tree),
    ])
    assert root_tree == _tree_sha1([("40000", "src", src_tree)]), (
        f"CreateCommit treeId {root_tree!r} != computed root tree "
        f"{_tree_sha1([('40000', 'src', src_tree)])!r}"
    )

    folder = cc.get_folder(repositoryName=repo, commitSpecifier=commit_id, folderPath="src")
    assert folder["commitId"] == commit_id, f"GetFolder commitId {folder['commitId']!r}"
    assert folder["folderPath"] == "src", f"GetFolder echoed folderPath {folder['folderPath']!r}"
    assert folder["treeId"] == src_tree, (
        f"GetFolder('src') treeId {folder['treeId']!r} != computed subtree {src_tree!r}"
    )

    files = {f["absolutePath"]: f for f in folder.get("files", [])}
    links = {s["absolutePath"]: s for s in folder.get("symbolicLinks", [])}
    subs = {d["absolutePath"]: d for d in folder.get("subFolders", [])}

    assert sorted(files) == ["src/a.txt", "src/run.sh"], (
        f"GetFolder('src').files listed {sorted(files)}; expected only the regular and "
        "executable blobs -- the symlink belongs in symbolicLinks and the directory in subFolders"
    )
    assert files["src/a.txt"]["fileMode"] == "NORMAL", f"a.txt fileMode {files['src/a.txt']['fileMode']!r}"
    assert files["src/a.txt"]["relativePath"] == "a.txt", f"a.txt relativePath {files['src/a.txt']['relativePath']!r}"
    assert files["src/a.txt"]["blobId"] == _blob_sha1(plain), f"a.txt blobId {files['src/a.txt']['blobId']!r}"
    assert files["src/run.sh"]["fileMode"] == "EXECUTABLE", (
        f"run.sh fileMode {files['src/run.sh']['fileMode']!r}; the executable bit did not round-trip"
    )
    assert files["src/run.sh"]["blobId"] == _blob_sha1(script), f"run.sh blobId {files['src/run.sh']['blobId']!r}"

    assert sorted(links) == ["src/link.txt"], (
        f"GetFolder('src').symbolicLinks listed {sorted(links)}, expected exactly ['src/link.txt']"
    )
    assert links["src/link.txt"]["fileMode"] == "SYMLINK", (
        f"link.txt fileMode {links['src/link.txt']['fileMode']!r}"
    )
    assert links["src/link.txt"]["relativePath"] == "link.txt", (
        f"link.txt relativePath {links['src/link.txt']['relativePath']!r}"
    )
    assert links["src/link.txt"]["blobId"] == _blob_sha1(link_target), (
        f"link.txt blobId {links['src/link.txt']['blobId']!r} != the id of the link target bytes "
        f"{_blob_sha1(link_target)!r} -- a symlink's blob content is its target path"
    )

    assert sorted(subs) == ["src/nested"], (
        f"GetFolder('src').subFolders listed {sorted(subs)}, expected exactly ['src/nested']"
    )
    assert subs["src/nested"]["treeId"] == nested_tree, (
        f"subFolder src/nested treeId {subs['src/nested']['treeId']!r} != computed {nested_tree!r}"
    )
    assert subs["src/nested"]["relativePath"] == "nested", (
        f"src/nested relativePath {subs['src/nested']['relativePath']!r}"
    )
    assert "blobId" not in subs["src/nested"], (
        f"a subFolder carries a blobId: {subs['src/nested']!r} -- trees are not blobs"
    )
    assert folder.get("subModules", []) == [], (
        f"GetFolder('src').subModules is {folder.get('subModules')!r}, expected empty"
    )

    # The nested folder is itself a partitioned listing, and its treeId is stable
    # whichever way it is reached.
    inner = cc.get_folder(repositoryName=repo, commitSpecifier=commit_id, folderPath="src/nested")
    assert inner["treeId"] == nested_tree, (
        f"GetFolder('src/nested') treeId {inner['treeId']!r} != {nested_tree!r} "
        "(same subtree reached directly vs via the parent listing)"
    )
    assert [f["absolutePath"] for f in inner.get("files", [])] == ["src/nested/b.txt"], (
        f"GetFolder('src/nested').files {[f['absolutePath'] for f in inner.get('files', [])]!r}"
    )
    assert inner.get("subFolders", []) == [], f"src/nested subFolders {inner.get('subFolders')!r}"

    # The executable bit is real content, not decoration: GetFile agrees with GetFolder.
    got = cc.get_file(repositoryName=repo, commitSpecifier=commit_id, filePath="src/run.sh")
    assert got["fileMode"] == "EXECUTABLE", f"GetFile run.sh fileMode {got['fileMode']!r}"
    assert got["fileContent"] == script, f"GetFile run.sh content {got['fileContent']!r}"


# ===== helpers =====

def _blob_sha1(content: bytes) -> str:
    """Git blob object id: sha1 of b'blob <bytelen>' + NUL + raw content.

    Not a security hash -- git's object-id construction is defined as SHA-1.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 - git object id


def _tree_sha1(entries) -> str:
    """Git tree object id from (mode, name, hex_sha) triples.

    Body is mode + ' ' + name + NUL + 20 raw sha bytes per entry, ordered by name -- and, per git's
    base_name_compare, a subtree sorts as if its name carried a trailing '/'.
    """
    body = b""
    for mode, name, sha in sorted(entries, key=lambda e: (e[1] + "/" if e[0] == "40000" else e[1]).encode("utf-8")):
        body += mode.encode("ascii") + b" " + name.encode("utf-8") + b"\x00" + binascii.unhexlify(sha)
    header = b"tree " + str(len(body)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + body).hexdigest()  # noqa: S324 - git object id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
