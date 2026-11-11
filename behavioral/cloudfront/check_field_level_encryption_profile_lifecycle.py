"""field-level-encryption-profile-lifecycle."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags

CHECK = "field-level-encryption-profile-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FieldLevelEncryptionProfile supports create->get->update->list->delete lifecycle."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()

    pk_ref = ctx.unique_name("sim2real-fle-pk-")
    pk = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": pk_ref,
            "Name": ctx.unique_name("sim2real-fle-pk-"),
            "EncodedKey": pem,
            "Comment": "sim2real-behav public key",
        }
    )
    pk_id = pk["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=pk_id, IfMatch=cf.get_public_key(Id=pk_id)["ETag"]))

    profile_name = ctx.unique_name("sim2real-fle-profile-")
    caller_ref = ctx.unique_name("sim2real-fle-profile-")
    created = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "Name": profile_name,
            "CallerReference": caller_ref,
            "Comment": "sim2real-behav v1",
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
    profile_id = created["FieldLevelEncryptionProfile"]["Id"]
    create_etag = created["ETag"]

    def _cleanup() -> None:
        try:
            etag = cf.get_field_level_encryption_profile_config(Id=profile_id)["ETag"]
        except cf.exceptions.NoSuchFieldLevelEncryptionProfile:
            return
        cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    got = cf.get_field_level_encryption_profile(Id=profile_id)
    cfg = got["FieldLevelEncryptionProfile"]["FieldLevelEncryptionProfileConfig"]
    assert cfg["Comment"] == "sim2real-behav v1", f"expected freshly-created Comment 'sim2real-behav v1', got {cfg['Comment']!r}"
    assert cfg["EncryptionEntities"]["Items"][0]["PublicKeyId"] == pk_id, (
        f"expected EncryptionEntities to echo PublicKeyId {pk_id!r}, got {cfg['EncryptionEntities']['Items'][0]['PublicKeyId']!r}"
    )

    listed = cf.list_field_level_encryption_profiles()
    ids = [i["Id"] for i in listed.get("FieldLevelEncryptionProfileList", {}).get("Items", [])]
    assert profile_id in ids, f"expected {profile_id!r} in ListFieldLevelEncryptionProfiles, got {ids!r}"

    updated = cf.update_field_level_encryption_profile(
        Id=profile_id,
        IfMatch=create_etag,
        FieldLevelEncryptionProfileConfig={
            "Name": profile_name,
            "CallerReference": caller_ref,
            "Comment": "sim2real-behav v2",
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
        },
    )
    assert updated["ETag"] != create_etag, f"expected UpdateFieldLevelEncryptionProfile to rotate the ETag, still {create_etag!r}"

    reread = cf.get_field_level_encryption_profile_config(Id=profile_id)
    reread_comment = reread["FieldLevelEncryptionProfileConfig"]["Comment"]
    assert reread_comment == "sim2real-behav v2", f"expected updated Comment 'sim2real-behav v2', got {reread_comment!r}"

    cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=updated["ETag"])

    deleted = False
    try:
        cf.get_field_level_encryption_profile(Id=profile_id)
    except cf.exceptions.NoSuchFieldLevelEncryptionProfile:
        deleted = True
    assert deleted, "expected GetFieldLevelEncryptionProfile to raise NoSuchFieldLevelEncryptionProfile after delete"

    mutation_rejected = False
    try:
        cf.update_field_level_encryption_profile(
            Id=profile_id,
            IfMatch=updated["ETag"],
            FieldLevelEncryptionProfileConfig={
                "Name": profile_name,
                "CallerReference": caller_ref,
                "Comment": "sim2real-behav v3",
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
            },
        )
    except cf.exceptions.NoSuchFieldLevelEncryptionProfile:
        mutation_rejected = True
    assert mutation_rejected, "expected UpdateFieldLevelEncryptionProfile on a deleted profile to raise NoSuchFieldLevelEncryptionProfile"


def _generate_rsa_public_key_pem() -> str:
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    pub = subprocess.run(["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True).stdout
    return pub.decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
