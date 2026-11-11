"""concurrent-put-file-same-parent-single-winner."""
from __future__ import annotations

import binascii
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-file-same-parent-single-winner"
GROUP = 'concurrency'
SERVICES = ['codecommit']
ERR_PARENT_OUTDATED = 'ParentCommitIdOutdatedException'
RACERS = 8


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of eight concurrent PutFile calls naming the same parentCommitId exactly one commits and seven
    raise ParentCommitIdOutdatedException; the tree holds only the winner's file, with its blob and
    tree ids, and every loser's path is absent."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"),
        tags={"sim2real": CHECK},
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    repo = meta["repositoryName"]

    seed = b"seed\n"
    base = cc.put_file(
        repositoryName=repo, branchName="main", filePath="seed.txt",
        fileContent=seed, commitMessage="seed",
    )["commitId"]

    payloads = {f"racer-{i}.txt": f"written by racer {i}\n".encode("utf-8") for i in range(RACERS)}

    def _racer(path, content):
        def _call():
            return cc.put_file(
                repositoryName=repo, branchName="main", filePath=path,
                fileContent=content, parentCommitId=base,
                commitMessage="concurrent write to " + path,
            )
        return _call

    order = list(payloads)
    results = _run_concurrent([_racer(p, payloads[p]) for p in order], timeout_s=90)

    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)
    assert successes == 1, (
        f"expected exactly 1 winner among {RACERS} writers sharing parent {base}, "
        f"got {successes} (codes={codes})"
    )
    assert codes.count(ERR_PARENT_OUTDATED) == RACERS - 1, (
        f"expected {RACERS - 1} x {ERR_PARENT_OUTDATED}, got {codes}"
    )

    winner_idx = [i for i, r in enumerate(results) if not isinstance(r, BaseException)][0]
    winner_path = order[winner_idx]
    winner = results[winner_idx]
    assert winner["blobId"] == _blob_sha1(payloads[winner_path]), (
        f"winning PutFile blobId {winner['blobId']!r} for {winner_path}"
    )

    tip = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert tip == winner["commitId"], (
        f"branch tip is {tip!r} but the only accepted commit was {winner['commitId']!r}"
    )

    expected_tree = _tree_sha1([
        ("100644", "seed.txt", _blob_sha1(seed)),
        ("100644", winner_path, _blob_sha1(payloads[winner_path])),
    ])
    assert winner["treeId"] == expected_tree, (
        f"the winning commit's treeId {winner['treeId']!r} != the tree holding seed.txt plus "
        f"only {winner_path} ({expected_tree!r}) -- the losers' writes leaked into the tree"
    )

    # Effect absent for every loser, present for the winner.
    present = []
    for path in order:
        try:
            got = cc.get_file(repositoryName=repo, commitSpecifier="main", filePath=path)
            assert got["fileContent"] == payloads[path], f"{path} content {got['fileContent']!r}"
            present.append(path)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            assert code == "FileDoesNotExistException", (
                f"GetFile {path} raised {code!r}, expected FileDoesNotExistException for a rejected writer"
            )
            assert message == f"Could not find path {path}", (
                f"expected the exact FileDoesNotExistException message AWS returns, got {message!r}"
            )
    assert present == [winner_path], (
        f"paths present at the tip are {present!r}, expected only the winner {winner_path!r}"
    )


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


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
