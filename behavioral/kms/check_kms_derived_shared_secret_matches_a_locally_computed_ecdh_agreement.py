"""kms-derived-shared-secret-matches-a-locally-computed-ecdh-agreement."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from behavioral_harness import tags

CHECK = "kms-derived-shared-secret-matches-a-locally-computed-ecdh-agreement"
GROUP = 'key_agreement'
SERVICES = ['kms']



def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window).

    The ARN guard keeps this teardown off AWS-managed keys and aliases.
    """
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return  # already PendingDeletion
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 2.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or raises AssertionError."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _der_spki(private_key) -> bytes:
    """The DER SubjectPublicKeyInfo of a locally generated key pair's public half."""
    return private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeriveSharedSecret's secret for a local peer key equals the locally computed P-256 ECDH
    secret against the KMS public key; a second peer yields a different secret; it is deterministic.
    """
    kms = ctx.client("kms")

    # KEY_AGREEMENT is a comparatively recent KeyUsage; a region without it fails loudly on the
    # specific ValidationException only.
    try:
        meta = kms.create_key(
            Description=ctx.unique_name("sim2real-behav-kms-ecdh-"),
            KeyUsage="KEY_AGREEMENT",
            KeySpec="ECC_NIST_P256",
            Tags=[{"TagKey": "sim2real", "TagValue": "kms-derive-shared-secret-vs-local-ecdh"}],
        )["KeyMetadata"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ValidationException":
            raise AssertionError(
                f"KeyUsage=KEY_AGREEMENT is not offered by kms in {ctx.region}: "
                f"{exc.response.get('Error', {}).get('Message')!r}"
            )
        raise
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    assert meta["KeyUsage"] == "KEY_AGREEMENT", meta["KeyUsage"]

    # Asymmetric CMK creation is asynchronous: the key pair is generated server-side.
    enabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=120,
        what=f"{key_arn} to reach Enabled",
    )
    assert enabled["KeyAgreementAlgorithms"] == ["ECDH"], (
        f"a KEY_AGREEMENT P-256 key must advertise exactly ECDH, got "
        f"{enabled.get('KeyAgreementAlgorithms')!r}"
    )

    pub = kms.get_public_key(KeyId=key_arn)
    assert pub["KeySpec"] == "ECC_NIST_P256", pub["KeySpec"]
    assert pub["KeyUsage"] == "KEY_AGREEMENT", pub["KeyUsage"]
    kms_pub = serialization.load_der_public_key(pub["PublicKey"])
    assert isinstance(kms_pub, ec.EllipticCurvePublicKey), type(kms_pub).__name__
    assert kms_pub.curve.name == "secp256r1", kms_pub.curve.name

    # Two independent local peer key pairs; KMS never sees either private half.
    peer1 = ec.generate_private_key(ec.SECP256R1())
    peer2 = ec.generate_private_key(ec.SECP256R1())
    der1, der2 = _der_spki(peer1), _der_spki(peer2)
    assert der1 != der2, "the two peer public keys must differ"

    resp1 = kms.derive_shared_secret(
        KeyId=key_arn, KeyAgreementAlgorithm="ECDH", PublicKey=der1
    )
    resp2 = kms.derive_shared_secret(
        KeyId=key_arn, KeyAgreementAlgorithm="ECDH", PublicKey=der2
    )
    s1, s2 = resp1["SharedSecret"], resp2["SharedSecret"]

    # The same curve computation done locally, independent of KMS.
    local1 = peer1.exchange(ec.ECDH(), kms_pub)
    local2 = peer2.exchange(ec.ECDH(), kms_pub)

    assert s1 == local1, (
        "the shared secret KMS derived does not match the local ECDH agreement over the same "
        "peer key and the same published public key — KMS is not doing P-256 ECDH with the "
        "private half of the key it published"
    )
    assert s2 == local2, (
        "the second peer key disagrees too, so the first match was not a coincidence"
    )
    assert s1 != s2, "two different peer keys must yield different shared secrets"
    assert len(s1) == 32, f"P-256 ECDH must yield a 32-byte secret, got {len(s1)}"

    # ECDH is a function of the two key pairs, so it is deterministic.
    again = kms.derive_shared_secret(
        KeyId=key_arn, KeyAgreementAlgorithm="ECDH", PublicKey=der1
    )
    assert again["SharedSecret"] == s1, (
        "ECDH must be deterministic for a fixed key pair; the second call returned a different "
        "secret"
    )

    assert resp1["KeyId"] == key_arn, resp1["KeyId"]
    assert resp1["KeyAgreementAlgorithm"] == "ECDH", resp1["KeyAgreementAlgorithm"]
    assert resp1["KeyOrigin"] == "AWS_KMS", resp1["KeyOrigin"]

    after = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert after["KeyState"] == "Enabled" and after["KeyUsage"] == "KEY_AGREEMENT", after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
