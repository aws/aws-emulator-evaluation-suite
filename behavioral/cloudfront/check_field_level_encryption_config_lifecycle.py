"""field-level-encryption-config-lifecycle."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags

CHECK = "field-level-encryption-config-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FieldLevelEncryptionConfig supports create->get->update->list->delete with state consistency."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")

    # AWS rejects a FieldLevelEncryptionConfig with no encryption profile mapping at all
    # (QueryArgProfileEmpty), so the config needs one real content-type profile mapping, hence a
    # real FieldLevelEncryptionProfile and a real public key.
    pem = _generate_rsa_public_key_pem()
    pk_ref = ctx.unique_name("sim2real-fle-cfg-pk-")
    pk = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": pk_ref,
            "Name": pk_ref,
            "EncodedKey": pem,
            "Comment": "sim2real-behav fle-cfg public key",
        }
    )
    pk_id = pk["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=pk_id, IfMatch=cf.get_public_key(Id=pk_id)["ETag"]))

    profile_ref = ctx.unique_name("sim2real-fle-cfg-profile-")
    profile = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "CallerReference": profile_ref,
            "Name": profile_ref,
            "Comment": "sim2real-behav fle-cfg profile",
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

    caller_ref = ctx.unique_name("sim2real-fle-cfg-")

    def _content_type_profile_config() -> dict:
        return {
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
        }

    # Real AWS accepts CreateFieldLevelEncryptionConfig with QueryArgProfileConfig omitted, but
    # UpdateFieldLevelEncryptionConfig rejects that same omission with IllegalUpdate
    # ("QueryArgProfileConfig is required for updates") — an update must always carry an explicit
    # QueryArgProfileConfig block (a genuine "no query-arg profiles configured" Quantity=0 block is
    # fine; it's OMITTING the key entirely that update rejects). Include it on both create and
    # update so the two calls submit the same shape.
    def _query_arg_profile_config() -> dict:
        return {"ForwardWhenQueryArgProfileIsUnknown": True, "QueryArgProfiles": {"Quantity": 0}}

    created = cf.create_field_level_encryption_config(
        FieldLevelEncryptionConfig={
            "CallerReference": caller_ref,
            "Comment": "sim2real-behav v1",
            "ContentTypeProfileConfig": _content_type_profile_config(),
            "QueryArgProfileConfig": _query_arg_profile_config(),
        }
    )
    cfg_id = created["FieldLevelEncryption"]["Id"]
    create_etag = created["ETag"]

    def _cleanup() -> None:
        try:
            etag = cf.get_field_level_encryption_config(Id=cfg_id)["ETag"]
        except cf.exceptions.NoSuchFieldLevelEncryptionConfig:
            return
        cf.delete_field_level_encryption_config(Id=cfg_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    got = cf.get_field_level_encryption(Id=cfg_id)
    got_comment = got["FieldLevelEncryption"]["FieldLevelEncryptionConfig"]["Comment"]
    assert got_comment == "sim2real-behav v1", f"expected comment 'sim2real-behav v1', got {got_comment!r}"
    got_cfg = cf.get_field_level_encryption_config(Id=cfg_id)
    assert got_cfg["ETag"] == create_etag, f"expected ETag {create_etag!r}, got {got_cfg['ETag']!r}"

    listed = cf.list_field_level_encryption_configs()
    ids = [i["Id"] for i in listed.get("FieldLevelEncryptionList", {}).get("Items", [])]
    assert cfg_id in ids, "newly created config must appear in ListFieldLevelEncryptionConfigs"

    updated = cf.update_field_level_encryption_config(
        Id=cfg_id,
        IfMatch=create_etag,
        FieldLevelEncryptionConfig={
            "CallerReference": caller_ref,
            "Comment": "sim2real-behav v2",
            "ContentTypeProfileConfig": _content_type_profile_config(),
            "QueryArgProfileConfig": _query_arg_profile_config(),
        },
    )
    update_etag = updated["ETag"]
    assert update_etag != create_etag, f"ETag must advance on update, still {update_etag!r}"

    reread = cf.get_field_level_encryption(Id=cfg_id)
    reread_comment = reread["FieldLevelEncryption"]["FieldLevelEncryptionConfig"]["Comment"]
    assert reread_comment == "sim2real-behav v2", f"expected comment 'sim2real-behav v2', got {reread_comment!r}"

    cf.delete_field_level_encryption_config(Id=cfg_id, IfMatch=update_etag)

    deleted = False
    try:
        cf.get_field_level_encryption(Id=cfg_id)
    except cf.exceptions.NoSuchFieldLevelEncryptionConfig:
        deleted = True
    assert deleted, "GetFieldLevelEncryption on a deleted config must raise NoSuchFieldLevelEncryptionConfig"

    listed_after = cf.list_field_level_encryption_configs()
    ids_after = [i["Id"] for i in listed_after.get("FieldLevelEncryptionList", {}).get("Items", [])]
    assert cfg_id not in ids_after, "deleted config must not appear in ListFieldLevelEncryptionConfigs"

    # Not just a read but a mutation on the dead id must also fail.
    mutation_rejected = False
    try:
        cf.update_field_level_encryption_config(
            Id=cfg_id,
            IfMatch=update_etag,
            FieldLevelEncryptionConfig={
                "CallerReference": caller_ref,
                "Comment": "sim2real-behav v3-should-not-apply",
                "ContentTypeProfileConfig": _content_type_profile_config(),
                "QueryArgProfileConfig": _query_arg_profile_config(),
            },
        )
    except cf.exceptions.NoSuchFieldLevelEncryptionConfig:
        mutation_rejected = True
    assert mutation_rejected, "UpdateFieldLevelEncryptionConfig on a deleted config must raise NoSuchFieldLevelEncryptionConfig"


def _generate_rsa_public_key_pem() -> str:
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    pub = subprocess.run(["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True).stdout
    return pub.decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
