"""field-level-encryption-profile-delete-in-use-rejected."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "field-level-encryption-profile-delete-in-use-rejected"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a field-level-encryption profile a config references fails with
    FieldLevelEncryptionProfileInUse and leaves it unchanged; once the config is gone the delete
    succeeds, and reading or deleting the profile again returns NoSuchFieldLevelEncryptionProfile."""
    cf = ctx.client("cloudfront")
    pub_key_pem = _generate_rsa_public_key_pem()

    pk_ref = ctx.unique_name("sim2real-fle-pk-")
    pk = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": pk_ref,
            "Name": pk_ref,
            "EncodedKey": pub_key_pem,
            "Comment": "sim2real test key",
        }
    )
    pk_id = pk["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(cf, pk_id))

    profile_ref = ctx.unique_name("sim2real-fle-profile-")
    profile = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "CallerReference": profile_ref,
            "Name": profile_ref,
            "Comment": "sim2real in-use test",
            "EncryptionEntities": {
                "Quantity": 1,
                "Items": [
                    {
                        "PublicKeyId": pk_id,
                        "ProviderId": "sim2real-provider",
                        "FieldPatterns": {"Quantity": 1, "Items": ["credit-card"]},
                    }
                ],
            },
        }
    )
    profile_id = profile["FieldLevelEncryptionProfile"]["Id"]
    profile_etag = profile["ETag"]
    ctx.on_cleanup(lambda: _delete_profile(cf, profile_id))

    cfg_ref = ctx.unique_name("sim2real-fle-cfg-")
    config = cf.create_field_level_encryption_config(
        FieldLevelEncryptionConfig={
            "CallerReference": cfg_ref,
            "Comment": "sim2real in-use test",
            "ContentTypeProfileConfig": {
                "ForwardWhenContentTypeIsUnknown": True,
                "ContentTypeProfiles": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Format": "URLEncoded",
                            "ProfileId": profile_id,
                            "ContentType": "application/x-www-form-urlencoded",
                        }
                    ],
                },
            },
        }
    )
    config_id = config["FieldLevelEncryption"]["Id"]
    ctx.on_cleanup(lambda: _delete_fle_config(cf, config_id))

    code, message = _error(
        lambda: cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=profile_etag)
    )
    assert code == "FieldLevelEncryptionProfileInUse", (
        f"expected FieldLevelEncryptionProfileInUse, got {code!r}"
    )
    in_use_message = (
        "The field level encryption profile is currently associated with a field level encryption config. "
        "Please disassociate the profile before deleting."
    )
    assert message == in_use_message, f"expected message {in_use_message!r}, got {message!r}"

    # the rejected delete must not have touched the profile: an independent read shows
    # it is still there, still referencing the same public key
    still = cf.get_field_level_encryption_profile(Id=profile_id)
    still_entities = still["FieldLevelEncryptionProfile"]["FieldLevelEncryptionProfileConfig"][
        "EncryptionEntities"
    ]["Items"]
    assert still_entities[0]["PublicKeyId"] == pk_id, (
        f"profile should be unchanged after rejected delete, got entities {still_entities!r}"
    )

    # once the referencing config is gone, deletion of the profile succeeds
    cf.delete_field_level_encryption_config(
        Id=config_id, IfMatch=cf.get_field_level_encryption_config(Id=config_id)["ETag"]
    )
    latest = cf.get_field_level_encryption_profile_config(Id=profile_id)
    cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=latest["ETag"])

    not_found_message = "The specified field level encryption profile does not exist."
    code_after, message_after = _error(lambda: cf.get_field_level_encryption_profile(Id=profile_id))
    assert code_after == "NoSuchFieldLevelEncryptionProfile", (
        f"expected NoSuchFieldLevelEncryptionProfile after delete, got {code_after!r}"
    )
    assert message_after == not_found_message, (
        f"expected message {not_found_message!r}, got {message_after!r}"
    )

    # the dead id is also unusable for further mutation, not just for reads
    code_dead_delete, message_dead_delete = _error(
        lambda: cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=latest["ETag"])
    )
    assert code_dead_delete == "NoSuchFieldLevelEncryptionProfile", (
        f"expected NoSuchFieldLevelEncryptionProfile on re-delete of a dead id, got {code_dead_delete!r}"
    )
    assert message_dead_delete == not_found_message, (
        f"expected message {not_found_message!r}, got {message_dead_delete!r}"
    )


def _generate_rsa_public_key_pem():
    require_tools("openssl")
    priv = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=30
    ).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True, timeout=30
    ).stdout
    return pub.decode("utf-8")


def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _delete_fle_config(cf, fle_id):
    from botocore.exceptions import ClientError

    try:
        cfg = cf.get_field_level_encryption_config(Id=fle_id)
        cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=cfg["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchFieldLevelEncryptionConfig":
            raise


def _delete_profile(cf, profile_id):
    from botocore.exceptions import ClientError

    try:
        cfg = cf.get_field_level_encryption_profile_config(Id=profile_id)
        cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=cfg["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchFieldLevelEncryptionProfile":
            raise


def _delete_public_key(cf, pk_id):
    from botocore.exceptions import ClientError

    try:
        cfg = cf.get_public_key_config(Id=pk_id)
        cf.delete_public_key(Id=pk_id, IfMatch=cfg["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicKey":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
