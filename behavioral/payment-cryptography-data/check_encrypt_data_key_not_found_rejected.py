"""encrypt-data-key-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encrypt-data-key-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography-data"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """EncryptData rejects a syntactically valid but non-existent KeyIdentifier with
    ResourceNotFoundException, while the same call against a real key (positive
    control) succeeds."""
    key = _create_pc_key(ctx)
    data = ctx.client("payment-cryptography-data")
    attrs = {"Symmetric": {"Mode": "ECB"}}

    # Positive control.
    data.encrypt_data(
        KeyIdentifier=key["arn"], PlainText="0011223344556677", EncryptionAttributes=attrs
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:payment-cryptography:{ctx.region}:{account_id}:key/0000000000000000"
    assert bogus_arn != key["arn"], f"bogus arn collided with real key arn {key['arn']!r}"

    err = _client_error(
        lambda: data.encrypt_data(
            KeyIdentifier=bogus_arn, PlainText="0011223344556677", EncryptionAttributes=attrs
        )
    )
    assert err is not None, "EncryptData against a nonexistent KeyIdentifier unexpectedly succeeded"
    code = err.response["Error"]["Code"]
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    # AWS returns an empty message for this refusal and names the key in ResourceId.
    msg = err.response["Error"].get("Message", "")
    assert msg == "", f"expected an empty message, got {msg!r}"
    assert err.response.get("ResourceId") == bogus_arn, (
        f"expected ResourceId {bogus_arn!r}, got {err.response.get('ResourceId')!r}"
    )


def _client_error(fn):
    try:
        fn()
    except ClientError as err:
        return err
    return None


def _create_pc_key(ctx):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_2KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
            "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
