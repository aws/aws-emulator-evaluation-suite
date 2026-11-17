"""field-level-encryption-profile-overlapping-field-patterns-rejected."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "field-level-encryption-profile-overlapping-field-patterns-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFieldLevelEncryptionProfile rejects two field patterns where one's wildcard prefix
    covers the other (ABC* overlaps AB*) with InvalidArgument; two non-overlapping prefixes
    create successfully (positive control)."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")
    pk_id = _create_public_key(ctx, cf)

    ref = ctx.unique_name("sim2real-fle-ov-")
    overlapping_entities = {
        "Quantity": 1,
        "Items": [
            {
                "PublicKeyId": pk_id,
                "ProviderId": "sim2real-provider",
                "FieldPatterns": {"Quantity": 2, "Items": ["ABC*", "AB*"]},
            }
        ],
    }

    code, message = _error(
        lambda: cf.create_field_level_encryption_profile(
            FieldLevelEncryptionProfileConfig={
                "Name": ref,
                "CallerReference": ref,
                "Comment": "sim2real-behav overlap",
                "EncryptionEntities": overlapping_entities,
            }
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    expected_message = (
        "The parameter FieldPattern cannot start with a prefix field pattern already present in "
        "the encryption entity."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listed = cf.list_field_level_encryption_profiles()["FieldLevelEncryptionProfileList"].get("Items", [])
    assert not any(i.get("Name") == ref for i in listed), (
        "a profile with overlapping field patterns was created despite InvalidArgument"
    )

    disjoint_entities = {
        "Quantity": 1,
        "Items": [
            {
                "PublicKeyId": pk_id,
                "ProviderId": "sim2real-provider",
                "FieldPatterns": {"Quantity": 2, "Items": ["ABC*", "XYZ*"]},
            }
        ],
    }
    created = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "Name": ref,
            "CallerReference": ref,
            "Comment": "sim2real-behav disjoint",
            "EncryptionEntities": disjoint_entities,
        }
    )
    profile_id = created["FieldLevelEncryptionProfile"]["Id"]

    def _cleanup() -> None:
        try:
            etag = cf.get_field_level_encryption_profile_config(Id=profile_id)["ETag"]
        except cf.exceptions.NoSuchFieldLevelEncryptionProfile:
            return
        cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    got = cf.get_field_level_encryption_profile(Id=profile_id)
    entities = got["FieldLevelEncryptionProfile"]["FieldLevelEncryptionProfileConfig"]["EncryptionEntities"]["Items"]
    got_patterns = entities[0]["FieldPatterns"]["Items"]
    assert sorted(got_patterns) == ["ABC*", "XYZ*"], (
        f"expected disjoint patterns ['ABC*', 'XYZ*'] to round-trip, got {sorted(got_patterns)!r}"
    )


def _error(fn):
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _create_public_key(ctx, cf) -> str:
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    pem = subprocess.run(["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True).stdout.decode(
        "ascii"
    )
    ref = ctx.unique_name("sim2real-fle-ov-pk-")
    pk = cf.create_public_key(
        PublicKeyConfig={"CallerReference": ref, "Name": ref, "EncodedKey": pem, "Comment": "sim2real-behav"}
    )
    pk_id = pk["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=pk_id, IfMatch=cf.get_public_key(Id=pk_id)["ETag"]))
    return pk_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
