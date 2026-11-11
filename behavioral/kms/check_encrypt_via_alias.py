"""encrypt-via-alias."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encrypt-via-alias"
GROUP = 'aliases'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt/Decrypt works when specifying key via alias name."""
    kms = ctx.client("kms")
    key_meta = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-encrypt-via-alias"}],
    )["KeyMetadata"]
    key_id = key_meta["KeyId"]
    key_arn = key_meta["Arn"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    alias_name = f"alias/sim2real-behav-{uuid.uuid4().hex[:8]}"
    kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    ctx.on_cleanup(lambda _a=alias_name: kms.delete_alias(AliasName=_a))
    # KMS aliases are eventually consistent: poll until the alias resolves.
    _deadline = time.monotonic() + 15
    while time.monotonic() < _deadline:
        try:
            kms.describe_key(KeyId=alias_name)
            break
        except ClientError:
            time.sleep(0.5)
    plaintext = b"encrypt-via-alias-test"

    enc_resp = kms.encrypt(KeyId=alias_name, Plaintext=plaintext)
    assert enc_resp["KeyId"] == key_arn, (
        f"Encrypt via alias {alias_name!r} must report the resolved key ARN "
        f"{key_arn!r}, got {enc_resp['KeyId']!r}"
    )
    dec_resp = kms.decrypt(CiphertextBlob=enc_resp["CiphertextBlob"], KeyId=key_id)
    assert dec_resp["Plaintext"] == plaintext, (
        f"decrypting ciphertext produced via alias {alias_name!r} must round-trip to the "
        f"original plaintext, got {dec_resp['Plaintext']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
