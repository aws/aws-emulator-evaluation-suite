"""disable-enable-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-enable-key"
GROUP = 'key_lifecycle'
SERVICES = ['kms']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call on a Disabled key, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableKey transitions state to Disabled and blocks crypto ops with DisabledException while
    the metadata plane stays readable; EnableKey restores both the state and cryptographic use."""
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("kms-disable-enable-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    disabled_message = f"{key['Arn']} is disabled."
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    # Positive control: crypto works before the key is touched.
    plaintext = b"payload-under-disable"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]

    kms.disable_key(KeyId=key_id)
    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyState"] == "Disabled", f"expected KeyState='Disabled', got {meta['KeyState']!r}"
    assert meta["Enabled"] is False, f"expected Enabled=False, got {meta['Enabled']!r}"

    encrypt_err = _client_error(lambda: kms.encrypt(KeyId=key_id, Plaintext=plaintext))
    assert encrypt_err.get("Code") == "DisabledException", (
        f"Encrypt on a Disabled key raised {encrypt_err.get('Code')!r}, expected 'DisabledException'"
    )
    assert encrypt_err.get("Message") == disabled_message, (
        f"Encrypt on a Disabled key returned message {encrypt_err.get('Message')!r}, expected {disabled_message!r}"
    )
    decrypt_err = _client_error(lambda: kms.decrypt(CiphertextBlob=ciphertext))
    assert decrypt_err.get("Code") == "DisabledException", (
        f"Decrypt on a Disabled key raised {decrypt_err.get('Code')!r}, expected 'DisabledException'"
    )
    assert decrypt_err.get("Message") == disabled_message, (
        f"Decrypt on a Disabled key returned message {decrypt_err.get('Message')!r}, expected {disabled_message!r}"
    )
    gdk_err = _client_error(lambda: kms.generate_data_key(KeyId=key_id, KeySpec="AES_256"))
    assert gdk_err.get("Code") == "DisabledException", (
        f"GenerateDataKey on a Disabled key raised {gdk_err.get('Code')!r}, expected 'DisabledException'"
    )
    assert gdk_err.get("Message") == disabled_message, (
        f"GenerateDataKey on a Disabled key returned message {gdk_err.get('Message')!r}, expected {disabled_message!r}"
    )

    # Metadata plane stays readable while crypto is blocked.
    tags_while_disabled = kms.list_resource_tags(KeyId=key_id)["Tags"]
    assert tags_while_disabled == [{"TagKey": "sim2real", "TagValue": CHECK}], (
        f"ListResourceTags on a Disabled key returned {tags_while_disabled!r}, "
        f"expected the tag set applied at creation"
    )

    kms.enable_key(KeyId=key_id)
    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyState"] == "Enabled", f"expected KeyState='Enabled', got {meta['KeyState']!r}"
    assert meta["Enabled"] is True, f"expected Enabled=True, got {meta['Enabled']!r}"

    restored = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert restored == plaintext, (
        f"Decrypt of the pre-disable ciphertext returned {restored!r} after EnableKey, "
        f"expected the original plaintext {plaintext!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
