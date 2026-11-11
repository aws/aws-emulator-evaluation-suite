"""get-parameters-for-export-token-reuse-semantics."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-parameters-for-export-token-reuse-semantics"
GROUP = "data-plane"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetParametersForExport generates a fresh ExportToken on every call by default, but
    ReuseLastGeneratedToken=True returns the same still-valid token instead of minting a new
    one (per the documented >=7-days-remaining-validity reuse rule)."""
    pc = ctx.client("payment-cryptography")

    first = pc.get_parameters_for_export(
        KeyMaterialType="TR34_KEY_BLOCK", SigningKeyAlgorithm="RSA_2048"
    )
    token1 = first["ExportToken"]
    # SigningKeyCertificate is PEM, base64-encoded on top (per API docs) -- decode before
    # checking for PEM markers, since the raw field value is the base64 envelope, not PEM text.
    cert_pem = _decode_cert(first["SigningKeyCertificate"])
    assert "-----BEGIN CERTIFICATE-----" in cert_pem, (
        f"expected a PEM certificate after base64 decode, got {cert_pem[:80]!r}"
    )

    reused = pc.get_parameters_for_export(
        KeyMaterialType="TR34_KEY_BLOCK",
        SigningKeyAlgorithm="RSA_2048",
        ReuseLastGeneratedToken=True,
    )
    token2 = reused["ExportToken"]
    assert token2 == token1, (
        f"ReuseLastGeneratedToken=True should return the prior token {token1!r}, got {token2!r}"
    )

    fresh = pc.get_parameters_for_export(
        KeyMaterialType="TR34_KEY_BLOCK", SigningKeyAlgorithm="RSA_2048"
    )
    token3 = fresh["ExportToken"]
    assert token3 != token1, (
        f"a call without ReuseLastGeneratedToken should mint a fresh token, but got back the "
        f"prior token {token1!r} again"
    )


def _decode_cert(value: str) -> str:
    import base64

    if "-----BEGIN CERTIFICATE-----" in value:
        return value
    try:
        decoded = base64.b64decode(value).decode("utf-8", errors="ignore")
    except Exception:
        return value
    return decoded


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
