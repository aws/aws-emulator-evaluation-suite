"""blob-id-is-content-addressed-git-sha1."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "blob-id-is-content-addressed-git-sha1"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutFile's blobId equals the git blob SHA-1 of the stored bytes (recomputed locally), GetBlob and
    GetFile return those bytes with matching metadata, and an absent id raises
    BlobIdDoesNotExistException."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": CHECK}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo = meta["repositoryName"]

    # Three payload shapes that separate byte-length from character-length and from
    # any text-encoding round trip: plain ascii, multibyte utf-8, and raw binary
    # containing NUL and every other byte value.
    cases = {
        "src/app.py": b"print('hello')\n",
        "src/unicode.txt": "café — über\n".encode("utf-8"),
        "src/binary.dat": bytes(range(256)),
    }

    parent = None
    blob_ids = {}
    for path, content in cases.items():
        kwargs = {
            "repositoryName": repo,
            "branchName": "main",
            "filePath": path,
            "fileContent": content,
            "commitMessage": "add " + path,
        }
        if parent is not None:
            kwargs["parentCommitId"] = parent
        out = cc.put_file(**kwargs)
        expected = _blob_sha1(content)
        assert out["blobId"] == expected, (
            f"PutFile blobId for {path} ({len(content)} bytes) is {out['blobId']!r}; "
            f"the git blob object id of those bytes is {expected!r}"
        )
        blob_ids[path] = out["blobId"]
        parent = out["commitId"]

    head = parent
    for path, content in cases.items():
        got = cc.get_file(repositoryName=repo, commitSpecifier=head, filePath=path)
        assert got["fileContent"] == content, (
            f"GetFile {path} returned {len(got['fileContent'])} bytes "
            f"{got['fileContent'][:40]!r}, stored {len(content)} bytes {content[:40]!r}"
        )
        assert got["blobId"] == blob_ids[path], (
            f"GetFile {path} blobId {got['blobId']!r} != PutFile blobId {blob_ids[path]!r}"
        )
        assert got["fileSize"] == len(content), (
            f"GetFile {path} fileSize {got['fileSize']} != byte length {len(content)}"
        )
        assert got["fileMode"] == "NORMAL", f"GetFile {path} fileMode {got['fileMode']!r}"
        # AWS returns the path with no leading slash, exactly as supplied (e.g. "docs/sub/notes.txt").
        assert got["filePath"] == path, f"GetFile echoed filePath {got['filePath']!r} for {path!r}"
        assert got["commitId"] == head, f"GetFile commitId {got['commitId']!r} != {head!r}"

        blob = cc.get_blob(repositoryName=repo, blobId=blob_ids[path])
        assert blob["content"] == content, (
            f"GetBlob {blob_ids[path]} returned {len(blob['content'])} bytes, "
            f"stored {len(content)} bytes for {path}"
        )

    # Content addressing runs the other way too: an id that is a well-formed sha1 but
    # was never stored must not resolve. An emulator that returns arbitrary bytes for
    # any id, or 200-with-empty, is not a content-addressed store.
    absent = _blob_sha1(b"this content was never committed to this repository\n")
    assert absent not in set(blob_ids.values()), "test payloads collided"
    try:
        resolved = cc.get_blob(repositoryName=repo, blobId=absent)
    except ClientError as exc:
        error = exc.response["Error"]
        code, message = error["Code"], error.get("Message")
    else:
        raise AssertionError(f"GetBlob resolved never-stored blob id {absent}: {resolved!r}")
    assert code == "BlobIdDoesNotExistException", f"GetBlob on absent id raised {code!r}"
    expected_message = f"AWS CodeCommit could not find the blob {absent} in the repository."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


def _blob_sha1(content: bytes) -> str:
    """Git blob object id: sha1 of the header b'blob <bytelen>' + NUL + raw content.

    Not a security hash -- this is the git object-id construction, which is defined to be SHA-1.
    """
    header = b"blob " + str(len(content)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + content).hexdigest()  # noqa: S324 - git object id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
