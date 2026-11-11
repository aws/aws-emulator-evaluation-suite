"""op-contract-get-field-level-encryption-profile-config."""
from __future__ import annotations

import subprocess
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "op-contract-get-field-level-encryption-profile-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFieldLevelEncryptionProfileConfig returns the created profile's config and 404s on a bogus Id."""
    cf = ctx.client("cloudfront")
    pubkey_pem = _generate_rsa_public_key_pem()

    key_name = ctx.unique_name("sim2real-flepk-")
    key_resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-flepk-ref-"),
            "Name": key_name,
            "EncodedKey": pubkey_pem,
            "Comment": "sim2real behavioral check public key",
        }
    )
    key_id = key_resp["PublicKey"]["Id"]
    key_resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=key_id, IfMatch=_current_etag(cf, "public_key", key_id)))

    profile_name = ctx.unique_name("sim2real-flep-")
    profile_resp = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "Name": profile_name,
            "CallerReference": ctx.unique_name("sim2real-flep-ref-"),
            "Comment": "sim2real behavioral check profile",
            "EncryptionEntities": {
                "Quantity": 1,
                "Items": [
                    {
                        "PublicKeyId": key_id,
                        "ProviderId": "sim2real-provider",
                        "FieldPatterns": {"Quantity": 1, "Items": ["creditcard"]},
                    }
                ],
            },
        }
    )
    profile_id = profile_resp["FieldLevelEncryptionProfile"]["Id"]
    ctx.on_cleanup(
        lambda: cf.delete_field_level_encryption_profile(
            Id=profile_id, IfMatch=_current_etag(cf, "field_level_encryption_profile", profile_id)
        )
    )

    # success path
    got = cf.get_field_level_encryption_profile_config(Id=profile_id)
    config = got["FieldLevelEncryptionProfileConfig"]
    assert config["Name"] == profile_name, f"expected Name {profile_name!r}, got {config['Name']!r}"
    assert config["EncryptionEntities"]["Quantity"] == 1, (
        f"expected EncryptionEntities.Quantity 1, got {config['EncryptionEntities']['Quantity']!r}"
    )
    assert config["EncryptionEntities"]["Items"][0]["PublicKeyId"] == key_id, (
        f"expected PublicKeyId {key_id!r}, got {config['EncryptionEntities']['Items'][0]['PublicKeyId']!r}"
    )
    assert got["ETag"], "GetFieldLevelEncryptionProfileConfig must return an ETag"

    # error boundary: unknown profile Id
    err, message = _error(lambda: cf.get_field_level_encryption_profile_config(Id=_absent_id_like(profile_id)))
    assert err == "NoSuchFieldLevelEncryptionProfile", f"expected NoSuchFieldLevelEncryptionProfile, got {err}"
    assert message == "The specified field level encryption profile does not exist.", (
        f"expected AWS's exact message, got {message!r}"
    )


def _generate_rsa_public_key_pem() -> str:
    require_tools("openssl")
    priv = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, timeout=20, check=True
    ).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=priv, capture_output=True, timeout=20, check=True
    ).stdout
    return pub.decode("utf-8")


def _current_etag(cf: Any, kind: str, resource_id: str) -> str:
    if kind == "public_key":
        return cf.get_public_key(Id=resource_id)["ETag"]
    if kind == "field_level_encryption_profile":
        return cf.get_field_level_encryption_profile(Id=resource_id)["ETag"]
    raise ValueError(f"unknown kind {kind}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _absent_id_like(real_id: str) -> str:
    """A well-formed Id that names nothing: the real Id's type prefix with its tail rotated.
    CloudFront refuses a malformed Id (one not shaped like this type's) as 'Id format is invalid'."""
    absent = real_id[0] + real_id[2:] + real_id[1]
    assert absent != real_id, f"cannot derive an absent Id from {real_id!r}"
    return absent


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
