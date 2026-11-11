"""op-contract-deleteFieldLevelEncryptionConfig."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteFieldLevelEncryptionConfig"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFieldLevelEncryptionConfig: a stale IfMatch is rejected distinctly, and
    a correct delete removes the config so Get reports NotFound."""
    cf = ctx.client("cloudfront")

    # Note: CloudFront rejects an *empty* QueryArgProfileConfig (Quantity==0)
    # with QueryArgProfileEmpty unconditionally -- even when
    # ForwardWhenQueryArgProfileIsUnknown is True, and even when the member is
    # simply omitted (the API still validates the implied empty structure).
    # So a real, non-empty QueryArgProfile is required, which in turn needs a
    # real FieldLevelEncryptionProfile (and therefore a real PublicKey) to
    # reference. Build that minimal chain here. ContentTypeProfileConfig, by
    # contrast, is fine with Quantity==0.
    pem = _generate_rsa_public_key_pem()
    public_key = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-pk-"),
            "Name": ctx.unique_name("sim2realpk"),
            "EncodedKey": pem,
            "Comment": "sim2real behavioral check",
        }
    )
    public_key_id = public_key["PublicKey"]["Id"]

    def _cleanup_public_key(public_key_id=public_key_id):
        try:
            fresh = cf.get_public_key(Id=public_key_id)
            cf.delete_public_key(Id=public_key_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicKey":
                raise

    ctx.on_cleanup(_cleanup_public_key)

    profile = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "Name": ctx.unique_name("sim2realflep"),
            "CallerReference": ctx.unique_name("sim2real-flep-"),
            "Comment": "sim2real behavioral check",
            "EncryptionEntities": {
                "Quantity": 1,
                "Items": [
                    {
                        "PublicKeyId": public_key_id,
                        "ProviderId": "sim2real-provider",
                        "FieldPatterns": {"Quantity": 1, "Items": ["credit-card"]},
                    }
                ],
            },
        }
    )
    profile_id = profile["FieldLevelEncryptionProfile"]["Id"]

    def _cleanup_profile(profile_id=profile_id):
        try:
            fresh = cf.get_field_level_encryption_profile(Id=profile_id)
            cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchFieldLevelEncryptionProfile":
                raise

    ctx.on_cleanup(_cleanup_profile)

    created = cf.create_field_level_encryption_config(
        FieldLevelEncryptionConfig={
            "CallerReference": ctx.unique_name("sim2real-flec-"),
            "Comment": "sim2real behavioral check",
            "ContentTypeProfileConfig": {
                "ForwardWhenContentTypeIsUnknown": True,
                "ContentTypeProfiles": {"Quantity": 0},
            },
            "QueryArgProfileConfig": {
                "ForwardWhenQueryArgProfileIsUnknown": True,
                "QueryArgProfiles": {
                    "Quantity": 1,
                    "Items": [{"QueryArg": "sim2real-profile", "ProfileId": profile_id}],
                },
            },
        }
    )
    config_id = created["FieldLevelEncryption"]["Id"]
    etag = created["ETag"]

    def _cleanup(config_id=config_id):
        try:
            fresh = cf.get_field_level_encryption(Id=config_id)
            cf.delete_field_level_encryption_config(Id=config_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchFieldLevelEncryptionConfig":
                raise

    ctx.on_cleanup(_cleanup)

    # error boundary: garbled IfMatch while the config still exists
    bad_code, bad_message = _error(
        lambda: cf.delete_field_level_encryption_config(Id=config_id, IfMatch='"bogus-etag"')
    )
    assert bad_code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {bad_code}"
    assert bad_message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {bad_message!r}"
    )

    # success path
    cf.delete_field_level_encryption_config(Id=config_id, IfMatch=etag)
    gone_code, gone_message = _error(lambda: cf.get_field_level_encryption(Id=config_id))
    assert gone_code == "NoSuchFieldLevelEncryptionConfig", (
        f"expected NoSuchFieldLevelEncryptionConfig, got {gone_code}"
    )
    assert gone_message == "The specified field level encryption config does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )


def _generate_rsa_public_key_pem() -> "str | None":
    import os
    import subprocess
    import tempfile

    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "priv.pem")
        pub = os.path.join(d, "pub.pem")
        subprocess.run(["openssl", "genrsa", "-out", priv, "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub], check=True, capture_output=True)
        with open(pub) as f:
            return f.read()


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
