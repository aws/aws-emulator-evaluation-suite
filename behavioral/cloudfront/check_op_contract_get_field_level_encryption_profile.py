"""op-contract-get-field-level-encryption-profile."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "op-contract-get-field-level-encryption-profile"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFieldLevelEncryptionProfile returns the entity/public-key wiring, 404s on unknown Id."""
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
                        "FieldPatterns": {"Quantity": 1, "Items": ["CreditCard*"]},
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

    # success-path contract
    got = cf.get_field_level_encryption_profile(Id=profile_id)
    cfg = got["FieldLevelEncryptionProfile"]["FieldLevelEncryptionProfileConfig"]
    assert cfg["Name"] == profile_name, f"expected Name {profile_name!r}, got {cfg['Name']!r}"
    assert cfg["EncryptionEntities"]["Items"][0]["PublicKeyId"] == key_id, (
        f"expected wired PublicKeyId {key_id!r}, got "
        f"{cfg['EncryptionEntities']['Items'][0]['PublicKeyId']!r}"
    )
    assert cfg["EncryptionEntities"]["Items"][0]["FieldPatterns"]["Items"] == ["CreditCard*"], (
        f"expected FieldPatterns ['CreditCard*'], got "
        f"{cfg['EncryptionEntities']['Items'][0]['FieldPatterns']['Items']!r}"
    )
    assert "ETag" in got, f"expected an ETag on the get response, got keys {sorted(got)!r}"

    # distinct error boundary: a well-formed profile Id that names nothing.
    code, message = _error(lambda: cf.get_field_level_encryption_profile(Id=_absent_id_like(profile_id)))
    assert code == "NoSuchFieldLevelEncryptionProfile", (
        f"expected NoSuchFieldLevelEncryptionProfile for an unknown Id, got {code}"
    )
    assert message == "The specified field level encryption profile does not exist.", (
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
    key = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=30
    )
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=key.stdout, capture_output=True, check=True, timeout=30
    )
    return pub.stdout.decode("ascii")


def _absent_id_like(real_id: str) -> str:
    """A well-formed Id that names nothing: the real Id's type prefix with its tail rotated.
    CloudFront refuses a malformed Id (one not shaped like this type's) as 'Id format is invalid'."""
    absent = real_id[0] + real_id[2:] + real_id[1]
    assert absent != real_id, f"cannot derive an absent Id from {real_id!r}"
    return absent


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
