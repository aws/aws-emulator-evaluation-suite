"""executable-and-symlink-file-modes-change-the-tree-id."""
from __future__ import annotations

import binascii
import hashlib

from behavioral_harness import tags

CHECK = "executable-and-symlink-file-modes-change-the-tree-id"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """The same bytes at mode EXECUTABLE and NORMAL share one blob id but produce different
    tree ids, and a SYMLINK stores its target as blob content at git tree mode 120000.
    Tree ids are recomputed locally, since fileMode must be a tree entry mode, not an attribute.
    """
    cc = ctx.client("codecommit")

    repo = ctx.unique_name("sim2real-behav-ccmode-")
    cc.create_repository(repositoryName=repo, tags={"sim2real": "ccmode"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    script = b"#!/bin/sh\necho hello from the fixture\n"
    link_target = b"bin/run.sh"

    normal = cc.put_file(repositoryName=repo, branchName="main", filePath="bin/run.sh",
                         fileContent=script, commitMessage="add the script at NORMAL")
    normal_subtree = _tree_sha1([("100644", "run.sh", _blob_sha1(script))])
    normal_root = _tree_sha1([("40000", "bin", normal_subtree)])
    assert normal["blobId"] == _blob_sha1(script), (
        f"PutFile at NORMAL reported blobId {normal['blobId']!r}; the git blob id of those "
        f"{len(script)} bytes is {_blob_sha1(script)!r}"
    )
    assert normal["treeId"] == normal_root, (
        f"the NORMAL commit's treeId is {normal['treeId']!r}; a root tree holding "
        f"bin/ at mode 100644 is {normal_root!r}"
    )

    # AWS accepts a fileMode change with byte-identical content: it is a tree change,
    # so it is not a NoChangeException.
    executable = cc.put_file(repositoryName=repo, branchName="main", filePath="bin/run.sh",
                             fileContent=script, fileMode="EXECUTABLE",
                             parentCommitId=normal["commitId"],
                             commitMessage="same bytes at EXECUTABLE")
    exec_subtree = _tree_sha1([("100755", "run.sh", _blob_sha1(script))])
    exec_root = _tree_sha1([("40000", "bin", exec_subtree)])

    assert executable["blobId"] == normal["blobId"], (
        f"the EXECUTABLE put reported blobId {executable['blobId']!r} and the NORMAL put "
        f"{normal['blobId']!r}; mode is tree metadata and must not change the object id"
    )
    assert executable["treeId"] != normal["treeId"], (
        f"both modes produced treeId {executable['treeId']!r}; the mode is part of the "
        f"tree entry, so the tree must differ"
    )
    assert executable["treeId"] == exec_root, (
        f"the EXECUTABLE commit's treeId is {executable['treeId']!r}; a root tree holding "
        f"bin/ at mode 100755 is {exec_root!r}"
    )

    folder = cc.get_folder(repositoryName=repo, commitSpecifier=executable["commitId"],
                          folderPath="bin")
    assert folder["treeId"] == exec_subtree, (
        f"GetFolder('bin') treeId is {folder['treeId']!r}, recomputed {exec_subtree!r}"
    )
    assert [f["fileMode"] for f in folder["files"]] == ["EXECUTABLE"], (
        f"GetFolder('bin') reports modes {[f['fileMode'] for f in folder['files']]!r}, "
        f"expected exactly ['EXECUTABLE']"
    )
    assert [f["absolutePath"] for f in folder["files"]] == ["bin/run.sh"], (
        f"GetFolder('bin') lists {[f['absolutePath'] for f in folder['files']]!r}"
    )

    # A symbolic link: the entry's content is its target string, at tree mode 120000.
    linked = cc.create_commit(
        repositoryName=repo, branchName="main", parentCommitId=executable["commitId"],
        commitMessage="add a symbolic link to the script",
        putFiles=[{"filePath": "run", "fileMode": "SYMLINK", "fileContent": link_target}])
    link_root = _tree_sha1([
        ("40000", "bin", exec_subtree),
        ("120000", "run", _blob_sha1(link_target)),
    ])
    assert linked["treeId"] == link_root, (
        f"the symlink commit's treeId is {linked['treeId']!r}; a root tree holding bin/ at "
        f"40000 and run at 120000 is {link_root!r} -- a SYMLINK must be a tree entry at "
        f"mode 120000, not a file with an attribute"
    )
    assert [f["fileMode"] for f in linked["filesAdded"]] == ["SYMLINK"], (
        f"CreateCommit reported filesAdded {linked['filesAdded']!r}, expected one entry at "
        f"fileMode 'SYMLINK'"
    )

    root = cc.get_folder(repositoryName=repo, commitSpecifier=linked["commitId"],
                        folderPath="/")
    assert [s["absolutePath"] for s in root["symbolicLinks"]] == ["run"], (
        f"GetFolder('/') symbolicLinks are "
        f"{[s['absolutePath'] for s in root['symbolicLinks']]!r}, expected ['run'] -- a "
        f"symlink must be partitioned as a link, never as an ordinary file"
    )
    assert root["symbolicLinks"][0]["fileMode"] == "SYMLINK", (
        f"the link's fileMode is {root['symbolicLinks'][0]['fileMode']!r}"
    )
    assert root["files"] == [], (
        f"GetFolder('/') also lists the link among files: {root['files']!r}"
    )
    assert root["symbolicLinks"][0]["blobId"] == _blob_sha1(link_target), (
        f"the link's blobId is {root['symbolicLinks'][0]['blobId']!r}; the git blob id of "
        f"the target string {link_target!r} is {_blob_sha1(link_target)!r}"
    )

    # The link's *content* is the target path, byte for byte, through both read paths.
    blob = cc.get_blob(repositoryName=repo, blobId=root["symbolicLinks"][0]["blobId"])
    assert blob["content"] == link_target, (
        f"GetBlob on the link returned {blob['content']!r}, expected the target "
        f"{link_target!r}"
    )
    as_file = cc.get_file(repositoryName=repo, commitSpecifier=linked["commitId"],
                         filePath="run")
    assert as_file["fileContent"] == link_target, (
        f"GetFile('run') returned {as_file['fileContent']!r}, expected the target "
        f"{link_target!r}"
    )
    assert as_file["fileMode"] == "SYMLINK", (
        f"GetFile('run') reports fileMode {as_file['fileMode']!r}, expected 'SYMLINK'"
    )
    assert as_file["fileSize"] == len(link_target), (
        f"GetFile('run') fileSize {as_file['fileSize']}, expected {len(link_target)} -- the "
        f"size of a link is the length of its target"
    )

    # The executable bit survived the commit that added the link: the modes are per-entry
    # state, not a property of the last write.
    still = cc.get_folder(repositoryName=repo, commitSpecifier=linked["commitId"],
                         folderPath="bin")
    assert still["treeId"] == exec_subtree, (
        f"after adding the link GetFolder('bin') treeId is {still['treeId']!r}, expected "
        f"the unchanged {exec_subtree!r}"
    )
    assert still["files"][0]["fileMode"] == "EXECUTABLE", (
        f"after adding the link bin/run.sh reports mode "
        f"{still['files'][0]['fileMode']!r}, expected 'EXECUTABLE'"
    )


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
