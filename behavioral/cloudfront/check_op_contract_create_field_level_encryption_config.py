"""op-contract-create-field-level-encryption-config."""
from __future__ import annotations

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "op-contract-create-field-level-encryption-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFieldLevelEncryptionConfig with a query-arg profile naming a real profile returns, and
    GetFieldLevelEncryptionConfig reads back, its Comment, ForwardWhenQueryArgProfileIsUnknown false and
    profile id, while one naming a nonexistent profile is refused with NoSuchFieldLevelEncryptionProfile."""

    cf = ctx.client("cloudfront")
    profile_id = _create_field_level_encryption_profile(ctx)
    caller_ref = ctx.unique_name("sim2real-behav-fle-")
    comment = "sim2real behavioral check"
    config = {
        "CallerReference": caller_ref,
        "Comment": comment,
        "QueryArgProfileConfig": {
            "ForwardWhenQueryArgProfileIsUnknown": False,
            "QueryArgProfiles": {
                "Quantity": 1,
                "Items": [{"QueryArg": "q", "ProfileId": profile_id}],
            },
        },
    }

    resp = cf.create_field_level_encryption_config(FieldLevelEncryptionConfig=config)
    fle_id = resp["FieldLevelEncryption"]["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_field_level_encryption_config(Id=fle_id, IfMatch=etag))

    returned = resp["FieldLevelEncryption"]["FieldLevelEncryptionConfig"]
    assert returned["Comment"] == comment
    assert returned["QueryArgProfileConfig"]["ForwardWhenQueryArgProfileIsUnknown"] is False
    assert returned["QueryArgProfileConfig"]["QueryArgProfiles"]["Items"][0]["ProfileId"] == profile_id

    # Independent read: the create call's own response is an echo, not proof the config was
    # actually persisted. GetFieldLevelEncryptionConfig is a different operation against the
    # same Id, so it must agree with what was created.
    independent = cf.get_field_level_encryption_config(Id=fle_id)
    assert independent["ETag"] == etag, f"ETag mismatch on independent read: {independent['ETag']!r} != {etag!r}"
    independent_cfg = independent["FieldLevelEncryptionConfig"]
    assert independent_cfg["Comment"] == comment, f"expected comment {comment!r}, got {independent_cfg['Comment']!r}"
    assert independent_cfg["QueryArgProfileConfig"]["ForwardWhenQueryArgProfileIsUnknown"] is False
    assert (
        independent_cfg["QueryArgProfileConfig"]["QueryArgProfiles"]["Items"][0]["ProfileId"] == profile_id
    ), "independent read must reflect the referenced profile ID"

    # Error boundary: a query-arg profile pointing at a nonexistent profile ID.
    bad_config = {
        "CallerReference": ctx.unique_name("sim2real-behav-fle-bad-"),
        "Comment": comment,
        "QueryArgProfileConfig": {
            "ForwardWhenQueryArgProfileIsUnknown": False,
            "QueryArgProfiles": {
                "Quantity": 1,
                "Items": [{"QueryArg": "q", "ProfileId": "NONEXISTENTPROFILEID1"}],
            },
        },
    }

    code, message = _error(lambda: cf.create_field_level_encryption_config(FieldLevelEncryptionConfig=bad_config))
    assert code == "NoSuchFieldLevelEncryptionProfile", f"unexpected code {code}"
    expected = "The specified field level encryption profile does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises,
    so a target that accepts what AWS refuses fails as an accepted call, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_field_level_encryption_profile(ctx):
    """Provisions a real public key + field-level-encryption profile, registers
    cleanup for both, and returns the profile Id."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()
    key_caller_ref = ctx.unique_name("sim2real-behav-pk-")
    key_resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": key_caller_ref,
            "Name": key_caller_ref,
            "EncodedKey": pem,
            "Comment": "sim2real behavioral check",
        }
    )
    public_key_id = key_resp["PublicKey"]["Id"]
    ctx.on_cleanup(
        lambda: cf.delete_public_key(
            Id=public_key_id, IfMatch=cf.get_public_key(Id=public_key_id)["ETag"]
        )
    )

    name = ctx.unique_name("sim2real-behav-fleprof-")
    profile_config = {
        "CallerReference": name,
        "Name": name,
        "Comment": "sim2real behavioral check",
        "EncryptionEntities": {
            "Quantity": 1,
            "Items": [
                {
                    "PublicKeyId": public_key_id,
                    "ProviderId": "sim2real-provider",
                    "FieldPatterns": {"Quantity": 1, "Items": ["CardNumber"]},
                }
            ],
        },
    }
    resp = cf.create_field_level_encryption_profile(FieldLevelEncryptionProfileConfig=profile_config)
    profile_id = resp["FieldLevelEncryptionProfile"]["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=etag))
    return profile_id


def _generate_rsa_public_key_pem():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")
    except Exception:
        pass

    import os
    import subprocess
    import tempfile

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        priv_path = os.path.join(tmp, "priv.pem")
        pub_path = os.path.join(tmp, "pub.pem")
        subprocess.run(
            ["openssl", "genrsa", "-out", priv_path, "2048"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "rsa", "-in", priv_path, "-pubout", "-out", pub_path],
            check=True,
            capture_output=True,
        )
        with open(pub_path) as fh:
            return fh.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
