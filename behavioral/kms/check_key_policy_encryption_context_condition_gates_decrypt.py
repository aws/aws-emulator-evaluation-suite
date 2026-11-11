"""key-policy-encryption-context-condition-gates-decrypt."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "key-policy-encryption-context-condition-gates-decrypt"
GROUP = 'key_policy'
SERVICES = ['kms']

ERR_ACCESS_DENIED = "AccessDeniedException"
ALLOWED_TENANT = "allowed"

def _refusal(fn):
    """The botocore Error if fn() raises ClientError, else the truthy marker "succeeded"."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    return "succeeded"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is true; raise AssertionError on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window; bills until then)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


def _restore_policy(kms, key_arn: str, policy: str) -> None:
    """Put back the policy document captured before this check modified it."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=policy)


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key-policy Deny on `kms:EncryptionContext:tenant` refuses Decrypt only for the other
    context; the allowed context, Encrypt and GenerateDataKey still work; removal restores access.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-ctxcond-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[
            {
                "TagKey": "sim2real",
                "TagValue": "kms-key-policy-encryption-context-condition-gates-decrypt",
            }
        ],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    original = kms.get_key_policy(KeyId=key_arn, PolicyName="default")["Policy"]
    doc = json.loads(original)
    assert isinstance(doc.get("Statement"), list) and doc["Statement"], original
    # LIFO: registered after the deletion cleanup, so the policy is restored FIRST.
    ctx.on_cleanup(lambda _a=key_arn, _p=original: _restore_policy(kms, _a, _p))

    plaintext = b"tenant-scoped-row"
    ok_ctx = {"tenant": ALLOWED_TENANT}
    bad_ctx = {"tenant": "other"}
    ct_ok = kms.encrypt(KeyId=key_arn, Plaintext=plaintext, EncryptionContext=ok_ctx)[
        "CiphertextBlob"
    ]
    ct_bad = kms.encrypt(KeyId=key_arn, Plaintext=plaintext, EncryptionContext=bad_ctx)[
        "CiphertextBlob"
    ]
    # Both decrypt before the policy change — this is the baseline the Deny must move.
    assert kms.decrypt(CiphertextBlob=ct_bad, KeyId=key_arn, EncryptionContext=bad_ctx)[
        "Plaintext"
    ] == plaintext, "baseline: Decrypt with the not-yet-denied context must succeed before any policy change"

    # Existing statements (incl. root kms:*) are kept; the Deny covers only kms:Decrypt,
    # so PutKeyPolicy can never be locked out.
    doc["Statement"] = list(doc["Statement"]) + [
        {
            "Sid": "sim2realDenyDecryptOutsideTenant",
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": "kms:Decrypt",
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {"kms:EncryptionContext:tenant": ALLOWED_TENANT}
            },
        }
    ]
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=json.dumps(doc))

    # Key-policy changes are eventually consistent; poll rather than sleep.
    denial = _poll_until(
        lambda: _refusal(
            lambda: kms.decrypt(
                CiphertextBlob=ct_bad, KeyId=key_arn, EncryptionContext=bad_ctx
            )
        ),
        lambda r: r != "succeeded",
        timeout_s=60,
        description="the appended Deny to take effect on Decrypt",
    )
    # KMS raises AccessDeniedException here although the KMS model lists it for no operation.
    assert denial["Code"] == ERR_ACCESS_DENIED, (
        f"Decrypt with a context the key policy denies must raise {ERR_ACCESS_DENIED} "
        f"(from KMS policy evaluation, not an IAM pre-flight denial), got {denial!r}"
    )
    # The message opens with the caller's ARN.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    deny_message = (
        f"User: {caller_arn} is not authorized to perform: kms:Decrypt on resource: {key_arn} "
        f"with an explicit deny in a resource-based policy"
    )
    assert denial["Message"] == deny_message, (
        f"expected {deny_message!r}, got {denial['Message']!r}"
    )

    assert kms.decrypt(CiphertextBlob=ct_ok, KeyId=key_arn, EncryptionContext=ok_ctx)[
        "Plaintext"
    ] == plaintext, "the allowed encryption context must still decrypt under the same policy"

    ct_bad2 = kms.encrypt(KeyId=key_arn, Plaintext=plaintext, EncryptionContext=bad_ctx)[
        "CiphertextBlob"
    ]
    assert ct_bad2 != ct_bad, (
        f"Encrypt must still succeed (and produce a fresh ciphertext) under the denied "
        f"context, because the Deny is scoped to kms:Decrypt only: got identical blob {ct_bad2!r}"
    )
    dk = kms.generate_data_key(KeyId=key_arn, KeySpec="AES_256", EncryptionContext=bad_ctx)
    assert len(dk["Plaintext"]) == 32, len(dk["Plaintext"])

    # The same blob decrypting after restore proves the refusal was policy, not corruption.
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", (
        f"the Decrypt refusal must be pure policy evaluation, not key damage: "
        f"expected KeyState Enabled, got {state!r}"
    )
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=original)

    def _try_decrypt_bad():
        """Return the Decrypt response, or None while the denial is still in effect."""
        try:
            return kms.decrypt(
                CiphertextBlob=ct_bad, KeyId=key_arn, EncryptionContext=bad_ctx
            )
        except ClientError as exc:
            assert exc.response.get("Error", {}).get("Code") == ERR_ACCESS_DENIED, exc.response
            assert exc.response["Error"].get("Message") == deny_message, exc.response
            return None

    plain_again = _poll_until(
        _try_decrypt_bad,
        lambda r: r is not None,
        timeout_s=60,
        description="the restored policy to re-allow Decrypt",
    )
    assert plain_again["Plaintext"] == plaintext, "restoring the policy must restore access"

    restored = json.loads(kms.get_key_policy(KeyId=key_arn, PolicyName="default")["Policy"])
    sids = {s.get("Sid") for s in restored["Statement"]}
    assert "sim2realDenyDecryptOutsideTenant" not in sids, sids
    assert kms.list_key_policies(KeyId=key_arn)["PolicyNames"] == ["default"], (
        kms.list_key_policies(KeyId=key_arn)["PolicyNames"]
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
