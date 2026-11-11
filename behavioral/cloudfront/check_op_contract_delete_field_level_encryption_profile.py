"""op-contract-deleteFieldLevelEncryptionProfile."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "op-contract-deleteFieldLevelEncryptionProfile"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFieldLevelEncryptionProfile: a stale IfMatch is rejected distinctly, and
    a correct delete removes the profile so Get reports NotFound."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()

    key_created = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-flep-key-"),
            "Name": ctx.unique_name("sim2real-flep-key-"),
            "EncodedKey": pem,
            "Comment": "sim2real behavioral check",
        }
    )
    key_id = key_created["PublicKey"]["Id"]

    def _cleanup_key(key_id=key_id):
        try:
            fresh = cf.get_public_key(Id=key_id)
            cf.delete_public_key(Id=key_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicKey":
                raise

    ctx.on_cleanup(_cleanup_key)

    profile_created = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "CallerReference": ctx.unique_name("sim2real-flep-"),
            "Name": ctx.unique_name("sim2real-flep-"),
            "Comment": "sim2real behavioral check",
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
    profile_id = profile_created["FieldLevelEncryptionProfile"]["Id"]
    etag = profile_created["ETag"]

    def _cleanup_profile(profile_id=profile_id):
        try:
            fresh = cf.get_field_level_encryption_profile(Id=profile_id)
            cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchFieldLevelEncryptionProfile":
                raise

    ctx.on_cleanup(_cleanup_profile)

    # error boundary: garbled IfMatch while the profile still exists
    bad_code, bad_message = _error(
        lambda: cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch='"bogus-etag"')
    )
    assert bad_code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {bad_code}"
    assert bad_message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {bad_message!r}"
    )

    # success path
    cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=etag)
    gone_code, gone_message = _error(lambda: cf.get_field_level_encryption_profile(Id=profile_id))
    assert gone_code == "NoSuchFieldLevelEncryptionProfile", (
        f"expected NoSuchFieldLevelEncryptionProfile, got {gone_code}"
    )
    assert gone_message == "The specified field level encryption profile does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _generate_rsa_public_key_pem():
    require_tools("openssl")
    priv = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=30
    ).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"],
        input=priv,
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout
    return pub.decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
