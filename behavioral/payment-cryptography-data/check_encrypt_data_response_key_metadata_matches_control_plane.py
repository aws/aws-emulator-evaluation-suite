"""encrypt-data-response-key-metadata-matches-control-plane."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encrypt-data-response-key-metadata-matches-control-plane"
GROUP = "state"
SERVICES = ["payment-cryptography-data"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """EncryptData called by alias returns the KeyArn and KeyCheckValue of the key CreateKey created, so
    the data plane resolves the alias to the control-plane key record rather than echoing the
    request."""
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
    kcv = key["KeyCheckValue"]
    ctx.on_cleanup(lambda: pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3))

    alias_name = "alias/" + ctx.unique_name("sim2real-pcd-").rstrip("-")
    pc.create_alias(AliasName=alias_name, KeyArn=arn)
    ctx.on_cleanup(lambda: pc.delete_alias(AliasName=alias_name))

    # The key must also be independently retrievable via GetKey with the same KCV.
    got = pc.get_key(KeyIdentifier=arn)["Key"]
    assert got["KeyArn"] == arn, f"expected {arn}, got {got['KeyArn']}"
    assert got["KeyCheckValue"] == kcv, f"expected {kcv}, got {got['KeyCheckValue']}"

    data = ctx.client("payment-cryptography-data")
    enc = data.encrypt_data(
        KeyIdentifier=alias_name,
        PlainText="0011223344556677",
        EncryptionAttributes={"Symmetric": {"Mode": "ECB"}},
    )
    assert enc["KeyArn"] == arn, (
        f"EncryptData resolved alias {alias_name} to {enc['KeyArn']!r}, expected the "
        f"control-plane key arn {arn!r} (a request-echoing stub would return the alias itself)"
    )
    assert enc["KeyCheckValue"] == kcv, f"expected {kcv}, got {enc['KeyCheckValue']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
