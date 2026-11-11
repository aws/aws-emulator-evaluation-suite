"""field-level-encryption-config-inconsistent-quantities-rejected."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "field-level-encryption-config-inconsistent-quantities-rejected"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFieldLevelEncryptionConfig rejects a ContentTypeProfiles.Quantity that doesn't
    match the number of Items with InconsistentQuantities before creating anything; a request
    with a matching Quantity/Items pair creates successfully (positive control)."""
    cf = ctx.client("cloudfront")
    profile_id = _create_profile(ctx, cf)

    caller_ref = ctx.unique_name("sim2real-fle-badqty-")
    item = {
        "Format": "URLEncoded",
        "ProfileId": profile_id,
        "ContentType": "application/x-www-form-urlencoded",
    }

    def _config(quantity: int) -> dict:
        return {
            "CallerReference": caller_ref,
            "Comment": caller_ref,
            "ContentTypeProfileConfig": {
                "ForwardWhenContentTypeIsUnknown": True,
                "ContentTypeProfiles": {"Quantity": quantity, "Items": [item]},
            },
        }

    # Break exactly one thing: Quantity says 2 but only one Item is supplied.
    code, message = _error(
        lambda: cf.create_field_level_encryption_config(FieldLevelEncryptionConfig=_config(2))
    )
    assert code == "InconsistentQuantities", f"expected InconsistentQuantities, got {code!r}"
    expected_message = (
        "The specified quantity of ContentTypeProfiles (2) does not match the actual quantity supplied (1)."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no config carrying this CallerReference/Comment was created.
    listed = cf.list_field_level_encryption_configs()["FieldLevelEncryptionList"].get("Items", [])
    assert not any(i.get("Comment") == caller_ref for i in listed), (
        "a field-level-encryption config was created despite InconsistentQuantities"
    )

    # Positive control: a matching Quantity/Items pair creates successfully.
    created = cf.create_field_level_encryption_config(FieldLevelEncryptionConfig=_config(1))
    cfg_id = created["FieldLevelEncryption"]["Id"]
    ctx.on_cleanup(lambda: _delete_config(cf, cfg_id))
    created_profiles = created["FieldLevelEncryption"]["FieldLevelEncryptionConfig"][
        "ContentTypeProfileConfig"
    ]["ContentTypeProfiles"]
    assert created_profiles["Quantity"] == 1
    assert created_profiles["Items"] == [item]


def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _generate_rsa_public_key_pem() -> str:
    require_tools("openssl")
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    pub = subprocess.run(["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True).stdout
    return pub.decode("ascii")


def _create_profile(ctx, cf) -> str:
    """A real FieldLevelEncryptionProfile for ContentTypeProfiles.Items[].ProfileId to
    reference, so the positive control creates a config AWS accepts end to end."""
    pem = _generate_rsa_public_key_pem()
    pk_ref = ctx.unique_name("sim2real-fle-badqty-pk-")
    pk = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": pk_ref,
            "Name": pk_ref,
            "EncodedKey": pem,
            "Comment": "sim2real-behav fle-badqty public key",
        }
    )
    pk_id = pk["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=pk_id, IfMatch=cf.get_public_key(Id=pk_id)["ETag"]))

    profile_ref = ctx.unique_name("sim2real-fle-badqty-profile-")
    profile = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "CallerReference": profile_ref,
            "Name": profile_ref,
            "Comment": "sim2real-behav fle-badqty profile",
            "EncryptionEntities": {
                "Quantity": 1,
                "Items": [
                    {
                        "PublicKeyId": pk_id,
                        "ProviderId": "sim2real-provider",
                        "FieldPatterns": {"Quantity": 1, "Items": ["CardNumber"]},
                    }
                ],
            },
        }
    )
    profile_id = profile["FieldLevelEncryptionProfile"]["Id"]

    def _delete_profile() -> None:
        try:
            etag = cf.get_field_level_encryption_profile_config(Id=profile_id)["ETag"]
        except cf.exceptions.NoSuchFieldLevelEncryptionProfile:
            return
        cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=etag)

    ctx.on_cleanup(_delete_profile)
    return profile_id


def _delete_config(cf, cfg_id: str) -> None:
    try:
        etag = cf.get_field_level_encryption_config(Id=cfg_id)["ETag"]
    except cf.exceptions.NoSuchFieldLevelEncryptionConfig:
        return
    cf.delete_field_level_encryption_config(Id=cfg_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
