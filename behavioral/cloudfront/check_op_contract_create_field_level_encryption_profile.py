"""op-contract-create-field-level-encryption-profile."""
from __future__ import annotations

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "op-contract-create-field-level-encryption-profile"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFieldLevelEncryptionProfile: a profile referencing a real, freshly
    uploaded public key round-trips its EncryptionEntities, and referencing a
    non-existent PublicKeyId is rejected with NoSuchPublicKey."""

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

    # Independent read: the create call's own echo is not proof it round-tripped.
    got = cf.get_field_level_encryption_profile(Id=profile_id)
    returned = got["FieldLevelEncryptionProfile"]["FieldLevelEncryptionProfileConfig"]
    assert returned["Name"] == name, f"expected Name {name!r}, got {returned.get('Name')!r}"
    entities = returned["EncryptionEntities"]["Items"]
    assert entities[0]["PublicKeyId"] == public_key_id, (
        f"expected PublicKeyId {public_key_id!r}, got {entities[0].get('PublicKeyId')!r}"
    )
    assert entities[0]["FieldPatterns"]["Items"] == ["CardNumber"], entities[0]["FieldPatterns"]["Items"]
    assert "ETag" in got, "GetFieldLevelEncryptionProfile response missing ETag"

    # Error boundary: referencing a public key that doesn't exist.
    bad_config = dict(profile_config)
    bad_config["CallerReference"] = ctx.unique_name("sim2real-behav-fleprof-bad-")
    bad_config["Name"] = bad_config["CallerReference"]
    bad_config["EncryptionEntities"] = {
        "Quantity": 1,
        "Items": [
            {
                "PublicKeyId": "NONEXISTENTPUBLICKEY1",
                "ProviderId": "sim2real-provider",
                "FieldPatterns": {"Quantity": 1, "Items": ["CardNumber"]},
            }
        ],
    }
    code, message = _error(
        lambda: cf.create_field_level_encryption_profile(FieldLevelEncryptionProfileConfig=bad_config)
    )
    assert code == "NoSuchPublicKey", f"expected NoSuchPublicKey, got {code}"
    expected = "The specified CloudFront public key does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
