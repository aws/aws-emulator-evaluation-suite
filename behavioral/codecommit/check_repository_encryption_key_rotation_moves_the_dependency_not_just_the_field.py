"""repository-encryption-key-rotation-moves-the-dependency-not-just-the-field."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "repository-encryption-key-rotation-moves-the-dependency-not-just-the-field"
GROUP = "data-plane"
SERVICES = ["codecommit"]

#: Flap budget for a disabled key to refuse a read; AWS does not enforce a disabled key on every
#: individual request.
_REFUSAL_TIMEOUT_S = 45.0
#: Budget for the re-enabled key to serve content again.
_RESTORE_TIMEOUT_S = 60.0
#: Floor for the absence-of-failure window; the real window is 3x the measured refusal latency.
_MIN_HOLD_S = 30.0
#: Consecutive identical reads demanded across the hold window.
_HOLD_READS = 4


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """UpdateRepositoryEncryptionKey reports the former key, keeps every git object id, and moves
    the KMS dependency: disabling the new key blocks reads, disabling the old one does not.

    Reference: https://docs.aws.amazon.com/codecommit/latest/APIReference/API_UpdateRepositoryEncryptionKey.html
    """
    cc = ctx.client("codecommit")
    kms = ctx.client("kms")

    key_a = _create_key(ctx, kms, "old")
    key_b = _create_key(ctx, kms, "new")
    assert _uuid(key_a["Arn"]) != _uuid(key_b["Arn"]), (
        f"the two CMKs share an id ({_uuid(key_a['Arn'])!r}); the rotation would be a no-op"
    )

    repo = ctx.unique_name("sim2real-behav-cckey-")
    created = cc.create_repository(
        repositoryName=repo, kmsKeyId=key_a["Arn"], tags={"sim2real": "cckey"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))
    repo_id = created["repositoryId"]
    assert _uuid(created["kmsKeyId"]) == _uuid(key_a["Arn"]), (
        f"CreateRepository reports kmsKeyId {created['kmsKeyId']!r}, expected the old CMK "
        f"{key_a['Arn']!r}"
    )

    nonce = f"content encrypted under the old key: {ctx.unique_name('n-')}\n".encode()
    commit_id = cc.put_file(
        repositoryName=repo,
        branchName="main",
        filePath="payload.txt",
        fileContent=nonce,
        commitMessage="written under the old key",
    )["commitId"]

    before_file = cc.get_file(
        repositoryName=repo, commitSpecifier=commit_id, filePath="payload.txt"
    )
    before_blob_id = before_file["blobId"]
    before_tree_id = cc.get_commit(repositoryName=repo, commitId=commit_id)["commit"]["treeId"]
    assert before_file["fileContent"] == nonce, (
        f"GetFile before the rotation returned {before_file['fileContent']!r}, expected the "
        f"{len(nonce)} bytes written, {nonce!r}"
    )

    rotated = cc.update_repository_encryption_key(
        repositoryName=repo, kmsKeyId=key_b["Arn"]
    )
    assert rotated["repositoryId"] == repo_id, (
        f"UpdateRepositoryEncryptionKey reports repositoryId {rotated['repositoryId']!r}, "
        f"expected the id CreateRepository returned, {repo_id!r}"
    )
    assert _uuid(rotated["kmsKeyId"]) == _uuid(key_b["Arn"]), (
        f"UpdateRepositoryEncryptionKey reports kmsKeyId {rotated['kmsKeyId']!r}, expected the "
        f"new CMK {key_b['Arn']!r}"
    )
    assert _uuid(rotated["originalKmsKeyId"]) == _uuid(key_a["Arn"]), (
        f"UpdateRepositoryEncryptionKey reports originalKmsKeyId "
        f"{rotated['originalKmsKeyId']!r}, expected the key the repository was CREATED under, "
        f"{key_a['Arn']!r}. Returning the new key here means the target has no notion of a "
        f"former key"
    )
    reread = cc.get_repository(repositoryName=repo)["repositoryMetadata"]
    assert _uuid(reread["kmsKeyId"]) == _uuid(key_b["Arn"]), (
        f"GetRepository reports kmsKeyId {reread['kmsKeyId']!r} after the rotation, expected "
        f"the new CMK {key_b['Arn']!r}"
    )
    assert _uuid(reread["kmsKeyId"]) != _uuid(key_a["Arn"]), (
        f"GetRepository still reports the OLD CMK {key_a['Arn']!r} after the rotation"
    )

    # Encryption is at rest, beneath the git object model, so no object id may move.
    after_file = cc.get_file(
        repositoryName=repo, commitSpecifier=commit_id, filePath="payload.txt"
    )
    assert after_file["blobId"] == before_blob_id, (
        f"the blobId for payload.txt changed across the rotation: {before_blob_id!r} -> "
        f"{after_file['blobId']!r}. Encryption is at rest, beneath the git object model, so a "
        f"rotation must not touch content-addressed ids"
    )
    assert after_file["fileContent"] == nonce, (
        f"GetFile after the rotation returned {after_file['fileContent']!r}, expected the "
        f"identical {len(nonce)} bytes {nonce!r}"
    )
    after_commit = cc.get_commit(repositoryName=repo, commitId=commit_id)["commit"]
    assert after_commit["treeId"] == before_tree_id, (
        f"the treeId for commit {commit_id!r} changed across the rotation: "
        f"{before_tree_id!r} -> {after_commit['treeId']!r}"
    )
    blob = cc.get_blob(repositoryName=repo, blobId=before_blob_id)
    assert blob["content"] == nonce, (
        f"GetBlob({before_blob_id}) after the rotation returned {blob['content']!r}, expected "
        f"the identical {len(nonce)} bytes {nonce!r} -- the new key must decrypt content "
        f"written under the old one"
    )

    _wait_key_state(kms, key_b["KeyId"], "Disabled", disable=True)
    # Polled: AWS does not enforce a disabled key on every individual request.
    refusal_started = time.monotonic()
    _poll_for_code(
        lambda: cc.get_blob(repositoryName=repo, blobId=before_blob_id),
        want="EncryptionKeyDisabledException",
        timeout_s=_REFUSAL_TIMEOUT_S,
        reason=(
            f"the NEW key {key_b['Arn']} is Disabled and GetBlob({before_blob_id}) must be "
            "refused; real AWS does not enforce a disabled key on every individual request, so "
            "the refusal is polled for rather than demanded on the first call"
        ),
    )
    refusal_latency = time.monotonic() - refusal_started

    _wait_key_state(kms, key_b["KeyId"], "Enabled", disable=False)
    _poll_for_value(
        lambda: cc.get_blob(repositoryName=repo, blobId=before_blob_id)["content"],
        want=nonce,
        timeout_s=_RESTORE_TIMEOUT_S,
        reason=(
            f"the re-enabled new key {key_b['Arn']} must serve the original {len(nonce)} bytes "
            "again -- without this leg a target that simply fails GetBlob always would pass the "
            "refusal above"
        ),
    )

    # Hold for 3x the refusal latency so a lagging old-key enforcement would have surfaced.
    _wait_key_state(kms, key_a["KeyId"], "Disabled", disable=True)
    hold_s = max(_MIN_HOLD_S, 3.0 * refusal_latency)
    interval = hold_s / _HOLD_READS
    seen = []
    for i in range(_HOLD_READS):
        time.sleep(interval)
        got = cc.get_blob(repositoryName=repo, blobId=before_blob_id)["content"]
        seen.append(got)
        assert got == nonce, (
            f"read {i + 1} of {_HOLD_READS}, {(i + 1) * interval:.0f}s after disabling the OLD "
            f"key {key_a['Arn']!r}, returned {got!r} instead of the original {len(nonce)} "
            f"bytes {nonce!r}. The rotation to {key_b['Arn']!r} did not move the repository's "
            f"KMS dependency -- it is still decrypting with the former key"
        )
    assert len(set(seen)) == 1, (
        f"the {_HOLD_READS} reads across the {hold_s:.0f}s hold returned "
        f"{len(set(seen))} distinct values; reads must be stable while the old key is Disabled"
    )

    disabled_code = _error_code(
        lambda: cc.update_repository_encryption_key(
            repositoryName=repo, kmsKeyId=key_a["Arn"]
        )
    )
    assert disabled_code == "EncryptionKeyDisabledException", (
        f"UpdateRepositoryEncryptionKey to the Disabled key {key_a['Arn']!r} returned "
        f"{disabled_code!r}, expected 'EncryptionKeyDisabledException'"
    )
    # message varies: AWS answers either 'KMS key <arn> is disabled' or 'KMS key The current KMS
    # key of this repository or <arn> is disabled' for the same call, so only the code is graded.
    final = cc.get_repository(repositoryName=repo)["repositoryMetadata"]
    assert _uuid(final["kmsKeyId"]) == _uuid(key_b["Arn"]), (
        f"GetRepository reports kmsKeyId {final['kmsKeyId']!r} after the refused rotation; the "
        f"refusal must have left the repository on {key_b['Arn']!r}"
    )


def _create_key(ctx, kms, role: str) -> dict:
    """A customer-managed CMK for this check, scheduled for deletion on teardown."""
    meta = kms.create_key(
        Description=f"sim2real codecommit re-key check ({role}) {ctx.unique_name('k-')}",
        Tags=[{"TagKey": "sim2real", "TagValue": "cckey"}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    assert meta["KeyState"] == "Enabled", (
        f"a freshly created CMK reports KeyState {meta['KeyState']!r}, expected 'Enabled'"
    )
    return meta


def _uuid(key_ref: str) -> str:
    """The bare key id from either a CMK ARN or a bare id, so the two forms compare equal."""
    return key_ref.rsplit("/", 1)[-1] if "/" in key_ref else key_ref


def _wait_key_state(kms, key_id: str, want: str, *, disable: bool, timeout_s: float = 60.0):
    """Flip a CMK and wait, bounded, for DescribeKey to agree. Raises on expiry."""
    (kms.disable_key if disable else kms.enable_key)(KeyId=key_id)
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if state == want:
            return
        time.sleep(2.0)
    raise AssertionError(
        f"CMK {key_id!r} reports KeyState {state!r} after {timeout_s}s, expected {want!r}; the "
        f"rest of the check depends on this transition having happened"
    )


def _error_code(fn):
    """The error code ``fn`` raised. RAISES on unexpected success, never a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(
        "the call was expected to be refused because the key it names is Disabled, but it "
        "SUCCEEDED -- the target is not consulting KMS key state at all"
    )


def _poll_for_code(fn, *, want: str, timeout_s: float, reason: str, interval_s: float = 3.0):
    """Poll until ``fn`` raises ``want``. RAISES on expiry naming expected vs last observed."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            seen = None
        except ClientError as exc:
            seen = exc.response["Error"]["Code"]
        if seen == want:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected error code {want!r} within {timeout_s}s, last observed "
                f"{'SUCCESS (the call was accepted)' if seen is None else repr(seen)}. "
                f"The window exists because: {reason}"
            )
        time.sleep(interval_s)


def _poll_for_value(fn, *, want, timeout_s: float, reason: str, interval_s: float = 3.0):
    """Poll until ``fn()`` equals ``want``. RAISES on expiry naming expected vs last observed.

    Errors from ``fn`` are recorded as the observed value so a failing read reports itself.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            seen = fn()
        except ClientError as exc:
            seen = f"<raised {exc.response['Error']['Code']}>"
        if seen == want:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected {want!r} within {timeout_s}s, last observed {seen!r}. The window "
                f"exists because: {reason}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
