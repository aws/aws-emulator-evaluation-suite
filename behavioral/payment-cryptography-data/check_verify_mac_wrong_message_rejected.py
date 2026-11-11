"""verify-mac-wrong-message-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-mac-wrong-message-rejected"
GROUP = "verification-semantics"
SERVICES = ["payment-cryptography-data"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """VerifyMac rejects a MAC computed over a different message than the one
    presented, while the same MAC verifies cleanly against the original message
    (positive control)."""
    key = _create_mac_key(ctx)
    data = ctx.client("payment-cryptography-data")
    message = "3b313038383439303031303733393431353d323430383232363030303733"
    tampered_message = "3b313038383439303031303733393431353d323430383232363030303734"
    assert tampered_message != message, (
        f"test fixture bug: tampered message must differ from the original, got {tampered_message!r} == {message!r}"
    )

    mac = data.generate_mac(
        KeyIdentifier=key["arn"],
        MessageData=message,
        GenerationAttributes={"Algorithm": "HMAC"},
    )["Mac"]

    # Positive control: verifying against the original message succeeds.
    data.verify_mac(
        KeyIdentifier=key["arn"],
        MessageData=message,
        Mac=mac,
        VerificationAttributes={"Algorithm": "HMAC"},
    )

    err = _client_error(
        lambda: data.verify_mac(
            KeyIdentifier=key["arn"],
            MessageData=tampered_message,
            Mac=mac,
            VerificationAttributes={"Algorithm": "HMAC"},
        )
    )
    assert err.response["Error"]["Code"] == "VerificationFailedException", (
        f"expected VerificationFailedException for a MAC verified against a different message than "
        f"it was generated over, got {err.response['Error']['Code']!r}"
    )
    assert err.response.get("Reason") == "INVALID_MAC", (
        f"expected Reason=INVALID_MAC, got {err.response.get('Reason')!r}"
    )
    msg = err.response["Error"]["Message"]
    assert msg == "Mac verification failed.", (
        f"expected message 'Mac verification failed.', got {msg!r}"
    )


def _client_error(fn):
    """Call fn(); return its ClientError. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a MAC verified against the wrong message is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err
    raise AssertionError(
        f"real AWS rejects VerifyMac against a tampered message, but it SUCCEEDED and returned {result!r}"
    )


def _create_mac_key(ctx):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "HMAC_SHA256",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": "TR31_M7_HMAC_KEY",
            "KeyModesOfUse": {"Generate": True, "Verify": True},
        },
        Tags=[{"Key": "simparity-check", "Value": "verify-mac-wrong-message-rejected"}],
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
