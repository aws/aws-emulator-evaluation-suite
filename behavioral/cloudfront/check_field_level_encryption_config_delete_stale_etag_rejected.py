"""field-level-encryption-config-delete-stale-etag-rejected."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "field-level-encryption-config-delete-stale-etag-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


def _generate_rsa_public_key_pem() -> str:
    """A throwaway 2048-bit RSA public key PEM — the minimal key CreatePublicKey accepts.
    Tries `cryptography` first, falls back to the `openssl` CLI."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pub_pem.decode("ascii")
    except ImportError:
        pass
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        pub_path = Path(tmp) / "pub.pem"
        subprocess.run(
            ["openssl", "genrsa", "-out", str(key_path), "2048"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "rsa", "-in", str(key_path), "-pubout", "-out", str(pub_path)],
            check=True,
            capture_output=True,
        )
        return pub_path.read_text()


def _create_query_arg_profile(ctx, cf) -> str:
    """A real field-level-encryption profile (backed by a real public key) so that the
    QueryArgProfiles list below is non-empty; CloudFront rejects an empty QueryArgProfiles
    list with QueryArgProfileEmpty regardless of ForwardWhenQueryArgProfileIsUnknown."""
    public_key_pem = _generate_rsa_public_key_pem()
    pub_key = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-flec-pk-cr-"),
            "Name": ctx.unique_name("sim2real-flec-pk-")[:64],
            "EncodedKey": public_key_pem,
            "Comment": "sim2real field-level-encryption-config-delete-stale-etag-rejected test key",
        }
    )
    public_key_id = pub_key["PublicKey"]["Id"]

    def _delete_public_key() -> None:
        try:
            e = cf.get_public_key(Id=public_key_id)["ETag"]
            cf.delete_public_key(Id=public_key_id, IfMatch=e)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicKey":
                raise

    ctx.on_cleanup(_delete_public_key)

    profile = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "Name": ctx.unique_name("sim2real-flec-profile-")[:64],
            "CallerReference": ctx.unique_name("sim2real-flec-profile-cr-"),
            "Comment": "sim2real field-level-encryption-config-delete-stale-etag-rejected test profile",
            "EncryptionEntities": {
                "Quantity": 1,
                "Items": [
                    {
                        "PublicKeyId": public_key_id,
                        "ProviderId": "sim2real-provider",
                        "FieldPatterns": {"Quantity": 1, "Items": ["CreditCardNumber"]},
                    }
                ],
            },
        }
    )
    profile_id = profile["FieldLevelEncryptionProfile"]["Id"]

    def _delete_profile() -> None:
        try:
            e = cf.get_field_level_encryption_profile(Id=profile_id)["ETag"]
            cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=e)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchFieldLevelEncryptionProfile":
                raise

    ctx.on_cleanup(_delete_profile)
    return profile_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFieldLevelEncryptionConfig with a stale If-Match ETag is rejected with
    PreconditionFailed and the config is NOT deleted; the same delete succeeds once the
    caller supplies the CURRENT ETag (positive control)."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-flec-stale-cr-")
    profile_id = _create_query_arg_profile(ctx, cf)

    def _profile_config(comment: str) -> dict:
        return {
            "CallerReference": caller_ref,
            "Comment": comment,
            "QueryArgProfileConfig": {
                "ForwardWhenQueryArgProfileIsUnknown": True,
                "QueryArgProfiles": {
                    "Quantity": 1,
                    "Items": [{"QueryArg": "sim2real-param", "ProfileId": profile_id}],
                },
            },
            "ContentTypeProfileConfig": {
                "ForwardWhenContentTypeIsUnknown": True,
                "ContentTypeProfiles": {"Quantity": 0},
            },
        }

    created = cf.create_field_level_encryption_config(
        FieldLevelEncryptionConfig=_profile_config("original-comment")
    )
    fle_id = created["FieldLevelEncryption"]["Id"]
    stale_etag = created["ETag"]

    def _cleanup() -> None:
        try:
            e = cf.get_field_level_encryption_config(Id=fle_id)["ETag"]
            cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=e)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchFieldLevelEncryptionConfig":
                raise

    ctx.on_cleanup(_cleanup)

    # Rotate the ETag with a real update, so `stale_etag` does not match the live version.
    cf.update_field_level_encryption_config(
        Id=fle_id, IfMatch=stale_etag, FieldLevelEncryptionConfig=_profile_config("rotated-comment")
    )

    code, message = _error(lambda: cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=stale_etag))
    assert code == "PreconditionFailed", f"expected 412 PreconditionFailed, got {code!r}"
    expected_message = (
        "The request failed because it didn't meet the preconditions in one or more request-header fields."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The forbidden effect did not happen: the config still exists with the rotated comment.
    still_there = cf.get_field_level_encryption_config(Id=fle_id)
    actual_comment = still_there["FieldLevelEncryptionConfig"]["Comment"]
    assert actual_comment == "rotated-comment", (
        f"expected the rejected delete to leave the config untouched (Comment='rotated-comment'), "
        f"got Comment={actual_comment!r}"
    )

    # Positive control: the same delete succeeds with the CURRENT ETag.
    current_etag = still_there["ETag"]
    cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=current_etag)

    not_found_message = "The specified field level encryption config does not exist."
    code2, message2 = _error(lambda: cf.get_field_level_encryption_config(Id=fle_id))
    assert code2 == "NoSuchFieldLevelEncryptionConfig", (
        f"expected NoSuchFieldLevelEncryptionConfig reading the deleted config, got {code2!r}"
    )
    assert message2 == not_found_message, f"expected message {not_found_message!r}, got {message2!r}"

    # A mutation on the deleted id must also fail with the specific not-found code, not
    # silently accept a stale ETag against a resource that does not exist.
    code3, message3 = _error(lambda: cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=current_etag))
    assert code3 == "NoSuchFieldLevelEncryptionConfig", (
        f"expected a second delete on the dead id to fail with NoSuchFieldLevelEncryptionConfig, got {code3!r}"
    )
    assert message3 == not_found_message, f"expected message {not_found_message!r}, got {message3!r}"


def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
