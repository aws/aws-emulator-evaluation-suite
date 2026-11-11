"""op-contract-get-field-level-encryption."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-field-level-encryption"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFieldLevelEncryption returns the stored CallerReference and Comment with an ETag; an unknown Id fails
    with NoSuchFieldLevelEncryptionConfig and its exact message."""
    cf = ctx.client("cloudfront")

    pem = _generate_rsa_public_key_pem()
    key_name = ctx.unique_name("sim2real-fle-pubkey-")
    created_key = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": key_name,
            "Name": key_name,
            "EncodedKey": pem,
            "Comment": "sim2real behavioral test public key",
        }
    )
    key_id = created_key["PublicKey"]["Id"]

    def _cleanup_key() -> None:
        try:
            cur = cf.get_public_key(Id=key_id)
            cf.delete_public_key(Id=key_id, IfMatch=cur["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicKey":
                raise

    ctx.on_cleanup(_cleanup_key)

    profile_name = ctx.unique_name("sim2real-fle-profile-")
    created_profile = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "Name": profile_name,
            "CallerReference": profile_name,
            "Comment": "sim2real behavioral test FLE profile",
            "EncryptionEntities": {
                "Quantity": 1,
                "Items": [
                    {
                        "PublicKeyId": key_id,
                        "ProviderId": "sim2real-provider",
                        "FieldPatterns": {"Quantity": 1, "Items": ["CardNumber"]},
                    }
                ],
            },
        }
    )
    profile_id = created_profile["FieldLevelEncryptionProfile"]["Id"]

    def _cleanup_profile() -> None:
        try:
            cur = cf.get_field_level_encryption_profile(Id=profile_id)
            cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=cur["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchFieldLevelEncryptionProfile":
                raise

    ctx.on_cleanup(_cleanup_profile)

    caller_ref = ctx.unique_name("sim2real-fle-")
    comment = "sim2real behavioral test FLE config"
    created = cf.create_field_level_encryption_config(
        FieldLevelEncryptionConfig={
            "CallerReference": caller_ref,
            "Comment": comment,
            "QueryArgProfileConfig": {
                "ForwardWhenQueryArgProfileIsUnknown": False,
                "QueryArgProfiles": {
                    "Quantity": 1,
                    "Items": [{"QueryArg": "sim2real-profile", "ProfileId": profile_id}],
                },
            },
            "ContentTypeProfileConfig": {
                "ForwardWhenContentTypeIsUnknown": True,
                "ContentTypeProfiles": {"Quantity": 0, "Items": []},
            },
        }
    )
    fle_id = created["FieldLevelEncryption"]["Id"]

    def _cleanup() -> None:
        try:
            cur = cf.get_field_level_encryption(Id=fle_id)
            cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=cur["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchFieldLevelEncryptionConfig":
                raise

    ctx.on_cleanup(_cleanup)

    # success-path contract
    got = cf.get_field_level_encryption(Id=fle_id)
    cfg = got["FieldLevelEncryption"]["FieldLevelEncryptionConfig"]
    assert cfg["CallerReference"] == caller_ref, (
        f"expected CallerReference {caller_ref!r}, got {cfg['CallerReference']!r}"
    )
    assert cfg["Comment"] == comment, f"expected Comment {comment!r}, got {cfg['Comment']!r}"
    assert "ETag" in got, f"expected ETag in GetFieldLevelEncryption response, got keys {list(got)}"

    # distinct error boundary: unknown Id
    code, message = _error(lambda: cf.get_field_level_encryption(Id=_absent_id_like(fle_id)))
    assert code == "NoSuchFieldLevelEncryptionConfig", f"unexpected code {code}"
    assert message == "The specified field level encryption config does not exist.", (
        f"expected AWS's exact message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises: accepting what AWS refuses
    is a finding in itself, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _generate_rsa_public_key_pem() -> "str | None":
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "priv.pem")
        pub = os.path.join(d, "pub.pem")
        subprocess.run(["openssl", "genrsa", "-out", priv, "2048"], check=True, capture_output=True)
        subprocess.run(
            ["openssl", "rsa", "-in", priv, "-pubout", "-out", pub], check=True, capture_output=True
        )
        with open(pub) as f:
            return f.read()


def _absent_id_like(real_id: str) -> str:
    """A well-formed Id that names nothing: the real Id's type prefix with its tail rotated.
    CloudFront refuses a malformed Id (one not shaped like this type's) as 'Id format is invalid'."""
    absent = real_id[0] + real_id[2:] + real_id[1]
    assert absent != real_id, f"cannot derive an absent Id from {real_id!r}"
    return absent


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
