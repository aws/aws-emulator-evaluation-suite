"""e2e-card-issuance-transaction-settlement-pipeline."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-card-issuance-transaction-settlement-pipeline"
GROUP = "e2e"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The issued CVV verifies, the issued PIN block verifies against its Visa PVV, the authorization
    MAC verifies, and ReEncryptData moves a DUKPT-encrypted settlement record to the network key (new
    KeyArn and ciphertext) so DecryptData recovers it."""
    data = ctx.client("payment-cryptography-data")

    # Stage 1: card issuance — generate and verify the card's CVV.
    cvk = _create_key(ctx, "TDES_2KEY", "TR31_C0_CARD_VERIFICATION_KEY", {"Generate": True, "Verify": True})
    cvv_attrs = {"CardVerificationValue1": {"CardExpiryDate": "1127", "ServiceCode": "121"}}
    cvv = data.generate_card_validation_data(
        KeyIdentifier=cvk["arn"], PrimaryAccountNumber=PAN, GenerationAttributes=cvv_attrs
    )["ValidationData"]
    data.verify_card_validation_data(
        KeyIdentifier=cvk["arn"], PrimaryAccountNumber=PAN,
        VerificationAttributes=cvv_attrs, ValidationData=cvv,
    )

    # Stage 2: PIN issuance — generate the cardholder's PIN block and Visa PVV.
    pvk = _create_key(ctx, "TDES_2KEY", "TR31_V2_VISA_PIN_VERIFICATION_KEY", {"Generate": True, "Verify": True})
    pek = _create_key(
        ctx, "TDES_2KEY", "TR31_P0_PIN_ENCRYPTION_KEY",
        {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    )
    issued = data.generate_pin_data(
        GenerationKeyIdentifier=pvk["arn"],
        EncryptionKeyIdentifier=pek["arn"],
        PrimaryAccountNumber=PAN,
        PinBlockFormat="ISO_FORMAT_0",
        GenerationAttributes={"VisaPin": {"PinVerificationKeyIndex": 1}},
    )
    pvv = issued["PinData"]["VerificationValue"]
    issued_block = issued["EncryptedPinBlock"]

    # Stage 3: point-of-sale authorization — the PIN block entered at the terminal
    # (here, the same PEK stands in for the acquirer's PEK) is verified against the
    # PVV minted at issuance, proving the two stages are consistent end-to-end.
    auth = data.verify_pin_data(
        VerificationKeyIdentifier=pvk["arn"],
        EncryptionKeyIdentifier=pek["arn"],
        VerificationAttributes={"VisaPin": {"PinVerificationKeyIndex": 1, "VerificationValue": pvv}},
        EncryptedPinBlock=issued_block,
        PrimaryAccountNumber=PAN,
        PinBlockFormat="ISO_FORMAT_0",
    )
    assert auth["VerificationKeyArn"] == pvk["arn"], (
        f"expected VerifyPinData to report the PVK used for verification "
        f"{pvk['arn']!r}, got {auth.get('VerificationKeyArn')!r}"
    )

    # Stage 4: MAC-authenticate the authorization message (ISO 8583-style field data).
    mac_key = _create_key(ctx, "HMAC_SHA256", "TR31_M7_HMAC_KEY", {"Generate": True, "Verify": True})
    auth_message = "3b" + PAN.encode().hex() + "3d3234303832323630303037303030"
    mac = data.generate_mac(
        KeyIdentifier=mac_key["arn"], MessageData=auth_message,
        GenerationAttributes={"Algorithm": "HMAC"},
    )["Mac"]
    data.verify_mac(
        KeyIdentifier=mac_key["arn"], MessageData=auth_message, Mac=mac,
        VerificationAttributes={"Algorithm": "HMAC"},
    )

    # Stage 5: network settlement — the terminal encrypts the settlement record under
    # its DUKPT-derived key; ReEncryptData moves it to the network's static key
    # without exposing the plaintext to the caller, and the network decrypts it.
    bdk = _create_key(ctx, "TDES_2KEY", "TR31_B0_BASE_DERIVATION_KEY", {"DeriveKey": True})
    network_key = _create_key(
        ctx, "TDES_2KEY", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    )
    settlement_record = "AABBCCDD11223344"
    ksn = "FFFF9876543210E00001"
    dukpt_attrs = {"Dukpt": {"KeySerialNumber": ksn, "Mode": "ECB"}}
    symmetric_attrs = {"Symmetric": {"Mode": "ECB"}}

    terminal_ciphertext = data.encrypt_data(
        KeyIdentifier=bdk["arn"], PlainText=settlement_record, EncryptionAttributes=dukpt_attrs
    )["CipherText"]

    reenc = data.re_encrypt_data(
        IncomingKeyIdentifier=bdk["arn"],
        OutgoingKeyIdentifier=network_key["arn"],
        CipherText=terminal_ciphertext,
        IncomingEncryptionAttributes=dukpt_attrs,
        OutgoingEncryptionAttributes=symmetric_attrs,
    )
    assert reenc["KeyArn"] == network_key["arn"], (
        f"expected ReEncryptData to report the outgoing network key "
        f"{network_key['arn']!r}, got {reenc.get('KeyArn')!r}"
    )
    assert reenc["CipherText"].upper() != terminal_ciphertext.upper(), (
        f"expected ReEncryptData to produce ciphertext distinct from the DUKPT-encrypted "
        f"input (still {terminal_ciphertext!r}), since it was moved to a different key"
    )

    recovered = data.decrypt_data(
        KeyIdentifier=network_key["arn"],
        CipherText=reenc["CipherText"],
        DecryptionAttributes=symmetric_attrs,
    )["PlainText"]
    assert recovered.upper() == settlement_record.upper(), (
        f"expected DecryptData under the network key to recover the original settlement "
        f"record {settlement_record!r}, got {recovered!r}"
    )


def _create_key(ctx, key_algorithm, key_usage, modes):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": key_algorithm,
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": key_usage,
            "KeyModesOfUse": modes,
        },
    )
    key = resp["Key"]
    arn = key["KeyArn"]

    def _cleanup():
        try:
            pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": arn, "kcv": key["KeyCheckValue"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


