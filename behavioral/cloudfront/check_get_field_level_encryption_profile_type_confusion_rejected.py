"""get-field-level-encryption-profile-type-confusion-rejected."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "get-field-level-encryption-profile-type-confusion-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFieldLevelEncryptionProfile must reject an Id belonging to a real PublicKey
    (a different, existing resource type) rather than resolving it as a profile."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()
    ref = ctx.unique_name("sim2real-flepk-typeconf-")
    created = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ref,
            "Name": ref,
            "EncodedKey": pem,
            "Comment": "sim2real cross-type isolation check",
        }
    )
    pubkey_id = created["PublicKey"]["Id"]

    def _cleanup():
        latest = cf.get_public_key(Id=pubkey_id)["ETag"]
        cf.delete_public_key(Id=pubkey_id, IfMatch=latest)

    ctx.on_cleanup(_cleanup)

    # Sanity: the id is real and resolves correctly as a PublicKey.
    real = cf.get_public_key(Id=pubkey_id)
    assert real["PublicKey"]["Id"] == pubkey_id, (
        f"positive control failed: expected GetPublicKey to echo Id {pubkey_id}, got {real['PublicKey'].get('Id')}"
    )

    # But it must NOT resolve when asked for as a FieldLevelEncryptionProfile.
    code, message = _error(lambda: cf.get_field_level_encryption_profile(Id=pubkey_id))
    assert code == "NoSuchFieldLevelEncryptionProfile", (
        f"a PublicKey Id must not resolve as a FieldLevelEncryptionProfile, got {code}"
    )
    # The Id carries the PublicKey type's shape, so CloudFront refuses it on format, not lookup.
    assert message == "Id format is invalid", (
        f"expected AWS's exact message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _generate_rsa_public_key_pem() -> str:
    require_tools("openssl")
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True
    ).stdout
    return pub.decode()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
