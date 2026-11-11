"""server-side-kms-decryption-transparent-on-get."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "server-side-kms-decryption-transparent-on-get"
GROUP = "server-side"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A secret encrypted with a customer-managed KMS key is transparently decrypted
    server-side on GetSecretValue without the caller performing any decrypt step."""
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")

    key_resp = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-smkey-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-audit", "TagValue": "true"}],
    )
    key_id = key_resp["KeyMetadata"]["KeyId"]
    key_arn = key_resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    name = ctx.unique_name("sim2real-behav-cmksecret-")
    secret_value = "cmk-protected-value-42"
    sm.create_secret(
        Name=name,
        SecretString=secret_value,
        KmsKeyId=key_id,
        Tags=[{"Key": "sim2real-audit", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    desc = sm.describe_secret(SecretId=name)
    assert desc["KmsKeyId"] in (key_id, key_arn), "DescribeSecret did not record the CMK used"

    # The caller performs zero KMS operations here -- GetSecretValue must hand back the
    # plaintext directly, proving server-side decryption happened transparently.
    got = sm.get_secret_value(SecretId=name)
    assert got["SecretString"] == secret_value, "plaintext did not survive CMK-encrypted round trip"

    # A subsequent write re-encrypted under the same CMK must also decrypt transparently.
    sm.put_secret_value(SecretId=name, SecretString=secret_value + "-v2")
    got2 = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
    expected_v2 = secret_value + "-v2"
    assert got2["SecretString"] == expected_v2, (
        f"expected {expected_v2!r} after re-encryption under the same CMK, got {got2['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
