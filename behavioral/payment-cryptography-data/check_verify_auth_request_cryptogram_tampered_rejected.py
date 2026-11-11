"""verify-auth-request-cryptogram-tampered-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-auth-request-cryptogram-tampered-rejected"
GROUP = "verification-semantics"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"
TRANSACTION_DATA = "00112233445566778899AABBCCDDEEFF"


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """VerifyAuthRequestCryptogram rejects an ARQC with one hex digit flipped, while
    the genuine ARQC generated for the same transaction data (positive control)
    verifies cleanly."""
    key = _create_imk_ac(ctx)
    data = ctx.client("payment-cryptography-data")
    session_attrs = {
        "Emv2000": {
            "PrimaryAccountNumber": PAN,
            "PanSequenceNumber": "00",
            "ApplicationTransactionCounter": "0001",
        }
    }

    arqc = data.generate_auth_request_cryptogram(
        KeyIdentifier=key["arn"],
        TransactionData=TRANSACTION_DATA,
        MajorKeyDerivationMode="EMV_OPTION_A",
        SessionKeyDerivationAttributes=session_attrs,
    )["AuthRequestCryptogram"]

    # Positive control: the genuine ARQC verifies.
    data.verify_auth_request_cryptogram(
        KeyIdentifier=key["arn"],
        TransactionData=TRANSACTION_DATA,
        AuthRequestCryptogram=arqc,
        MajorKeyDerivationMode="EMV_OPTION_A",
        SessionKeyDerivationAttributes=session_attrs,
    )

    flipped_char = "1" if arqc[0] != "1" else "2"
    tampered_arqc = flipped_char + arqc[1:]
    assert tampered_arqc != arqc, f"tamper produced no change: {tampered_arqc!r} == {arqc!r}"

    err = _client_error(
        lambda: data.verify_auth_request_cryptogram(
            KeyIdentifier=key["arn"],
            TransactionData=TRANSACTION_DATA,
            AuthRequestCryptogram=tampered_arqc,
            MajorKeyDerivationMode="EMV_OPTION_A",
            SessionKeyDerivationAttributes=session_attrs,
        )
    )
    assert err is not None, "tampered ARQC was accepted; expected VerificationFailedException"
    assert err.response["Error"]["Code"] == "VerificationFailedException", (
        f"expected VerificationFailedException, got {err.response['Error']['Code']!r}"
    )
    assert err.response.get("Reason") == "INVALID_AUTH_REQUEST_CRYPTOGRAM", (
        f"expected Reason=INVALID_AUTH_REQUEST_CRYPTOGRAM, got {err.response.get('Reason')!r}"
    )
    msg = err.response["Error"]["Message"]
    assert msg == "Auth request cryptogram verification failed.", (
        f"expected message 'Auth request cryptogram verification failed.', got {msg!r}"
    )


def _client_error(fn):
    try:
        fn()
    except ClientError as err:
        return err
    return None


def _create_imk_ac(ctx):
    pc = ctx.client("payment-cryptography")
    tag_value = ctx.unique_name("sim2real-val-")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_2KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
            "KeyModesOfUse": {"DeriveKey": True},
        },
        Tags=[{"Key": "sim2real-env", "Value": tag_value}],
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
