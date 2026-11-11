"""identical-file-content-dedupes-to-one-blob-id."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "identical-file-content-dedupes-to-one-blob-id"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Identical bytes at different paths and in different repositories share one blob id equal to the
    locally computed git SHA-1, while bytes that differ by one byte get another id."""
    cc = ctx.client("codecommit")
    shared = b"# shared library header\nversion = 1\n"
    other = b"# shared library header\nversion = 2\n"

    meta_a = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "ccdedup"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta_a["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo_a = meta_a["repositoryName"]

    created = cc.create_commit(
        repositoryName=repo_a,
        branchName="main",
        commitMessage="two identical files and one different",
        putFiles=[
            {"filePath": "dup/one.txt", "fileMode": "NORMAL", "fileContent": shared},
            {"filePath": "dup/two.txt", "fileMode": "NORMAL", "fileContent": shared},
            {"filePath": "dup/three.txt", "fileMode": "NORMAL", "fileContent": other},
        ],
    )
    commit_id = created["commitId"]

    folder = cc.get_folder(repositoryName=repo_a, commitSpecifier=commit_id, folderPath="dup")
    by_path = {f["absolutePath"]: f for f in folder["files"]}
    assert sorted(by_path) == ["dup/one.txt", "dup/three.txt", "dup/two.txt"], (
        f"GetFolder('dup') listed {sorted(by_path)}"
    )

    expected_shared = _blob_sha1(shared)
    expected_other = _blob_sha1(other)
    assert expected_shared != expected_other, "test payloads collided"

    id_one = by_path["dup/one.txt"]["blobId"]
    id_two = by_path["dup/two.txt"]["blobId"]
    id_three = by_path["dup/three.txt"]["blobId"]

    assert id_one == expected_shared, f"dup/one.txt blobId {id_one!r} != {expected_shared!r}"
    assert id_two == expected_shared, f"dup/two.txt blobId {id_two!r} != {expected_shared!r}"
    assert id_one == id_two, (
        f"identical content at two paths produced two blob ids: {id_one!r} vs {id_two!r} "
        "-- blobId is being derived from something other than the content"
    )
    assert id_three == expected_other, f"dup/three.txt blobId {id_three!r} != {expected_other!r}"
    assert id_three != id_one, "one-byte-different content produced the same blob id"

    # One stored object serves both paths, and it holds the shared bytes.
    assert cc.get_blob(repositoryName=repo_a, blobId=id_one)["content"] == shared, (
        "GetBlob on the deduplicated id did not return the shared bytes"
    )

    # Object ids are global, not per-repository: the same bytes at an unrelated path in
    # a second repository hash to the same id.
    meta_b = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "ccdedup"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta_b["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo_b = meta_b["repositoryName"]

    put_b = cc.put_file(
        repositoryName=repo_b,
        branchName="trunk",
        filePath="totally/other/place.txt",
        fileContent=shared,
        commitMessage="same bytes, different repo, different path, different branch",
    )
    assert put_b["blobId"] == expected_shared, (
        f"same bytes in a second repository produced blobId {put_b['blobId']!r}, "
        f"expected the same content-addressed id {expected_shared!r}"
    )
    assert cc.get_blob(repositoryName=repo_b, blobId=expected_shared)["content"] == shared, (
        "GetBlob in the second repository did not return the shared bytes"
    )


def _blob_sha1(content: bytes) -> str:
    """Git blob object id: sha1 of the header b'blob <bytelen>' + NUL + raw content.

    Not a security hash -- this is git's object-id construction, defined as SHA-1.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 - git object id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
