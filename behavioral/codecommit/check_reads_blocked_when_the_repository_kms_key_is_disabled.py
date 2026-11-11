"""reads-blocked-when-the-repository-kms-key-is-disabled."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reads-blocked-when-the-repository-kms-key-is-disabled"
GROUP = 'error-semantics'
SERVICES = ['codecommit']

#: How long each read/write path is given to be observed refusing once the key is Disabled.
#: AWS enforces quickly but not on every individual request, so this is a flap budget.
_REFUSAL_TIMEOUT_S = 45.0


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """With the repository's customer-managed KMS key disabled, reads and writes fail with
    EncryptionKeyDisabledException; re-enabling the key makes GetBlob return the original bytes.

    Reference: https://docs.aws.amazon.com/codecommit/latest/userguide/encryption.html
    """
    cc = ctx.client("codecommit")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # A key policy that lets CodeCommit use the key, plus the account root so the check
    # can still administer it after CodeCommit is cut off.
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-cckms-"),
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "AllowAccountAdministration", "Effect": "Allow",
                 "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                 "Action": "kms:*", "Resource": "*"},
                {"Sid": "AllowCodeCommit", "Effect": "Allow",
                 "Principal": {"Service": "codecommit.amazonaws.com"},
                 "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
                            "kms:GenerateDataKey*", "kms:DescribeKey"],
                 "Resource": "*"},
            ],
        }),
        Tags=[{"TagKey": "sim2real", "TagValue": "cckms"}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    # A CMK cannot be deleted, only scheduled, and 7 days is the shortest window AWS
    # accepts -- so this is the strongest undo available, and the key stays PendingDeletion
    # after the run.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))
    assert key["KeyState"] == "Enabled", f"a new CMK reports KeyState {key['KeyState']!r}"

    repo = ctx.unique_name("sim2real-behav-cckms-r-")
    meta = cc.create_repository(repositoryName=repo, kmsKeyId=key_arn,
                               tags={"sim2real": "cckms"})["repositoryMetadata"]
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))
    assert meta["kmsKeyId"] == key_arn, (
        f"CreateRepository reports kmsKeyId {meta['kmsKeyId']!r}, expected the supplied "
        f"{key_arn!r} -- the repository is not on the key under test"
    )

    nonce = ctx.unique_name("payload-").encode("ascii") + b"\n"
    put = cc.put_file(repositoryName=repo, branchName="main", filePath="secret.txt",
                      fileContent=nonce, commitMessage="seed")
    blob_id = put["blobId"]

    # Barrier: the positive path works *before* anything is broken. Without this a
    # failure after disable_key could just as well be a repository that was never
    # readable.
    baseline = cc.get_blob(repositoryName=repo, blobId=blob_id)["content"]
    assert baseline == nonce, (
        f"GetBlob before the key was touched returned {baseline!r}, expected {nonce!r} -- "
        f"the CMK-encrypted repository must be readable to begin with"
    )

    # Break exactly one thing. Registered immediately before the mutation it undoes, so
    # LIFO runs it ahead of delete_repository, which itself needs a usable key.
    ctx.on_cleanup(lambda: _swallow(lambda: kms.enable_key(KeyId=key_arn)))
    kms.disable_key(KeyId=key_arn)
    state = _poll_key_state(kms, key_arn, "Disabled", timeout_s=120.0)
    assert state == "Disabled", (
        f"the key is still {state!r} two minutes after disable_key; the check cannot "
        f"observe the disabled read path"
    )

    # Key state reaches CodeCommit eventually, so poll for the refusal rather than sleeping.
    disabled = ("EncryptionKeyDisabledException", f"KMS key {key_arn} is disabled")
    refusal = _poll_for_refusal(lambda: cc.get_blob(repositoryName=repo, blobId=blob_id),
                                timeout_s=180.0)
    assert (refusal.get("Code"), refusal.get("Message")) == disabled, (
        f"GetBlob against a repository whose CMK is disabled raised {refusal!r}, expected "
        f"{disabled!r}"
    )

    # Effect absent: no read path hands back the content. Each path is polled until it
    # refuses: with the key Disabled, AWS enforcement is not synchronous per request and a
    # path can briefly answer normally before it refuses again.
    for label, call in (
        ("GetBlob", lambda: cc.get_blob(repositoryName=repo, blobId=blob_id)),
        ("GetFile", lambda: cc.get_file(repositoryName=repo, commitSpecifier="main",
                                        filePath="secret.txt")),
        ("GetBranch", lambda: cc.get_branch(repositoryName=repo, branchName="main")),
    ):
        observed = _poll_for_refusal(call, timeout_s=_REFUSAL_TIMEOUT_S)
        assert (observed.get("Code"), observed.get("Message")) == disabled, (
            f"{label} on a repository with a disabled CMK answered {observed!r} for the "
            f"whole {_REFUSAL_TIMEOUT_S:.0f}s window, expected "
            f"{disabled!r} -- no read path may serve content while the "
            f"key is disabled"
        )

    # Writes are refused too. Polled for the same reason, with a fresh file path per attempt
    # and the tip re-anchored on any attempt that lands: a flapped success moves main, and a
    # stale parentCommitId would then raise a PARENT error that hides the answer.
    write_refusal, parent, attempt = None, put["commitId"], 0
    write_deadline = time.monotonic() + _REFUSAL_TIMEOUT_S
    while True:
        attempt += 1
        try:
            landed = cc.put_file(
                repositoryName=repo, branchName="main",
                filePath=f"written-while-disabled-{attempt}.txt",
                fileContent=b"written while the key was disabled\n",
                parentCommitId=parent, commitMessage="should not land")
        except ClientError as exc:
            write_refusal = (exc.response.get("Error", {}).get("Code"),
                             exc.response.get("Error", {}).get("Message"))
            break
        parent = landed["commitId"]
        if time.monotonic() >= write_deadline:
            break
        time.sleep(5.0)
    assert write_refusal == disabled, (
        f"PutFile against a repository with a disabled CMK answered {write_refusal!r} for the "
        f"whole {_REFUSAL_TIMEOUT_S:.0f}s window ({attempt} attempts), expected "
        f"{disabled!r}"
    )

    # Positive control, same file, same call: re-enable and the original bytes come back.
    kms.enable_key(KeyId=key_arn)
    state = _poll_key_state(kms, key_arn, "Enabled", timeout_s=120.0)
    assert state == "Enabled", f"the key is still {state!r} two minutes after enable_key"
    restored = _poll_for_success(lambda: cc.get_blob(repositoryName=repo, blobId=blob_id),
                                 timeout_s=180.0)
    assert restored is not None, (
        "GetBlob still fails three minutes after the key was re-enabled; the refusal was "
        "not caused by the key state"
    )
    assert restored["content"] == nonce, (
        f"after enable_key GetBlob returned {len(restored['content'])} bytes "
        f"{restored['content']!r}, expected the original {len(nonce)} bytes {nonce!r}"
    )
    # And the file path resolves again, at the same content-addressed id. Polled because the
    # enforcement flap runs in this direction too.
    again = _poll_for_success(
        lambda: cc.get_file(repositoryName=repo, commitSpecifier="main",
                            filePath="secret.txt"),
        timeout_s=_REFUSAL_TIMEOUT_S)
    assert again is not None, (
        f"GetFile still fails {_REFUSAL_TIMEOUT_S:.0f}s after the key was re-enabled, while "
        f"GetBlob already succeeded -- the path must come back with the key"
    )
    assert again["blobId"] == blob_id, (
        f"after enable_key GetFile reports blobId {again['blobId']!r}, expected the "
        f"original {blob_id!r} -- the object must survive the key being cycled"
    )
    assert again["fileContent"] == nonce, (
        f"after enable_key GetFile returned {again['fileContent']!r}, expected {nonce!r}"
    )


# ===== helpers =====

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_key_state(kms, key_arn: str, want: str, *, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    while state != want and time.monotonic() < deadline:
        time.sleep(2.0)
        state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    return state


def _poll_for_refusal(fn, *, timeout_s: float) -> dict:
    """Poll a call until it raises, returning the AWS Error record ({} if it never did)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {})
        if time.monotonic() >= deadline:
            return {}
        time.sleep(5.0)


def _poll_for_success(fn, *, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() >= deadline:
                return None
            time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
