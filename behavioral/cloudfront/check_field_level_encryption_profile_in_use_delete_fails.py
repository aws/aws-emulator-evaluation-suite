"""field-level-encryption-profile-in-use-delete-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource. Idempotent: a resource
    already deleted by the check body is not a cleanup failure."""
    try:
        resp = get_fn(Id=resource_id)
    except ClientError as exc:
        if (exc.response.get("Error", {}).get("Code") or "").startswith("NoSuch"):
            return
        raise
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

def _generate_rsa_public_key_pem():
    """Generate a fresh, structurally-valid RSA public key PEM for CreatePublicKey tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("ascii")

CHECK = "field-level-encryption-profile-in-use-delete-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a field-level-encryption profile a config references fails with FieldLevelEncryptionProfileInUse
    and the exact message and leaves the profile on its public key; once the config is deleted the delete
    succeeds and GetFieldLevelEncryptionProfile returns NoSuchFieldLevelEncryptionProfile."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()
    pk_name = ctx.unique_name("sim2real-behav-fle-inuse-pk-")
    pk_resp = cf.create_public_key(
        PublicKeyConfig={"CallerReference": pk_name, "Name": pk_name, "EncodedKey": pem}
    )
    key_id = pk_resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_public_key, cf.delete_public_key, key_id))

    profile_name = ctx.unique_name("sim2real-behav-fle-inuse-profile-")
    profile_resp = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "Name": profile_name,
            "CallerReference": profile_name,
            "Comment": "in-use test",
            "EncryptionEntities": {
                "Quantity": 1,
                "Items": [
                    {
                        "PublicKeyId": key_id,
                        "ProviderId": "sim2real-behav-provider",
                        "FieldPatterns": {"Quantity": 1, "Items": ["credit-card-number"]},
                    }
                ],
            },
        }
    )
    profile_id = profile_resp["FieldLevelEncryptionProfile"]["Id"]
    profile_etag = profile_resp["ETag"]
    ctx.on_cleanup(
        lambda: _force_delete(
            cf.get_field_level_encryption_profile, cf.delete_field_level_encryption_profile, profile_id
        )
    )

    config_name = ctx.unique_name("sim2real-behav-fle-inuse-cfg-")
    config_resp = cf.create_field_level_encryption_config(
        FieldLevelEncryptionConfig={
            "CallerReference": config_name,
            "Comment": "in-use test",
            "ContentTypeProfileConfig": {
                "ForwardWhenContentTypeIsUnknown": True,
                "ContentTypeProfiles": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "ContentType": "application/x-www-form-urlencoded",
                            "Format": "URLEncoded",
                            "ProfileId": profile_id,
                        }
                    ],
                },
            },
            "QueryArgProfileConfig": {
                "ForwardWhenQueryArgProfileIsUnknown": True,
                "QueryArgProfiles": {"Quantity": 0, "Items": []},
            },
        }
    )
    config_id = config_resp["FieldLevelEncryption"]["Id"]
    ctx.on_cleanup(
        lambda: _force_delete(
            cf.get_field_level_encryption_config, cf.delete_field_level_encryption_config, config_id
        )
    )

    code, message = _error(
        lambda: cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=profile_etag)
    )
    assert code == "FieldLevelEncryptionProfileInUse", (
        f"expected FieldLevelEncryptionProfileInUse, got {code}"
    )
    in_use_message = (
        "The field level encryption profile is currently associated with a field level encryption config. "
        "Please disassociate the profile before deleting."
    )
    assert message == in_use_message, f"expected message {in_use_message!r}, got {message!r}"

    # Still there and still referencing the same public key.
    still = cf.get_field_level_encryption_profile(Id=profile_id)
    entities = still["FieldLevelEncryptionProfile"]["FieldLevelEncryptionProfileConfig"][
        "EncryptionEntities"
    ]["Items"]
    assert entities[0]["PublicKeyId"] == key_id, (
        f"expected profile to still reference {key_id}, got {entities}"
    )

    # Restore: remove the referencing config, then the identical delete call succeeds.
    config_etag = cf.get_field_level_encryption_config(Id=config_id)["ETag"]
    cf.delete_field_level_encryption_config(Id=config_id, IfMatch=config_etag)

    latest_profile_etag = cf.get_field_level_encryption_profile(Id=profile_id)["ETag"]
    cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=latest_profile_etag)

    code_after, message_after = _error(lambda: cf.get_field_level_encryption_profile(Id=profile_id))
    assert code_after == "NoSuchFieldLevelEncryptionProfile", (
        f"expected NoSuchFieldLevelEncryptionProfile after restore-and-delete, got {code_after}"
    )
    not_found_message = "The specified field level encryption profile does not exist."
    assert message_after == not_found_message, (
        f"expected message {not_found_message!r}, got {message_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
