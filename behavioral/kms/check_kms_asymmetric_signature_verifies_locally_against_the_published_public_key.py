"""kms-asymmetric-signature-verifies-locally-against-the-published-public-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from behavioral_harness import tags

CHECK = "kms-asymmetric-signature-verifies-locally-against-the-published-public-key"
GROUP = 'sign_verify'
SERVICES = ['kms']


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted.

    The minimum PendingWindowInDays is 7; the ARN guard keeps this off aliases and AWS-managed keys.
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
    """Poll fn() until predicate(value) is true; return the value or raise on timeout."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _local_verify(public_key, signature: bytes, message: bytes) -> bool:
    """Verify a KMS signature with pyca/cryptography. True, False, or it raises on a bad key type.

    KMS signs PSS with a salt equal to the digest length, so DIGEST_LENGTH is required;
    MAX_LENGTH would reject a correct signature.
    """
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
                ),
                hashes.SHA256(),
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            raise AssertionError(f"unexpected public key type {type(public_key).__name__}")
        return True
    except InvalidSignature:
        return False


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """For RSA_2048 (RSASSA_PSS) and ECC_NIST_P256 (ECDSA) keys, Sign's output verifies locally
    against GetPublicKey's DER key, a one-bit message change fails, and KMS Verify agrees; the
    published key matches its KeySpec and advertised SigningAlgorithms.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/offline-public-key.html
    """
    kms = ctx.client("kms")
    message = b"a-message-signed-by-kms-and-verified-off-aws"
    tampered = message[:-1] + bytes([message[-1] ^ 1])
    assert tampered != message and len(tampered) == len(message), (tampered, message)

    cases = (
        ("RSA_2048", "RSASSA_PSS_SHA_256"),
        ("ECC_NIST_P256", "ECDSA_SHA_256"),
    )
    verified = []
    for key_spec, sign_alg in cases:
        meta = kms.create_key(
            Description=ctx.unique_name(f"sim2real-behav-kms-locsig-{key_spec.lower()}-"),
            KeyUsage="SIGN_VERIFY",
            KeySpec=key_spec,
            Tags=[{"TagKey": "sim2real", "TagValue": "kms-local-signature-verification"}],
        )["KeyMetadata"]
        key_arn = meta["Arn"]
        ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

        # Asymmetric CMK creation is asynchronous: the key pair is generated server-side.
        _poll_until(
            lambda _a=key_arn: kms.describe_key(KeyId=_a)["KeyMetadata"],
            lambda m: m["KeyState"] == "Enabled",
            timeout_s=120,
            what=f"{key_arn} to reach Enabled",
        )

        signed = kms.sign(
            KeyId=key_arn, Message=message, MessageType="RAW", SigningAlgorithm=sign_alg
        )
        assert signed["KeyId"] == key_arn, signed["KeyId"]
        assert signed["SigningAlgorithm"] == sign_alg, signed["SigningAlgorithm"]
        assert len(signed["Signature"]) > 0, signed

        pub = kms.get_public_key(KeyId=key_arn)
        assert pub["KeySpec"] == key_spec, (
            f"GetPublicKey advertises KeySpec {pub['KeySpec']!r}, the key was created as "
            f"{key_spec!r}"
        )
        assert pub["KeyUsage"] == "SIGN_VERIFY", pub["KeyUsage"]
        assert sign_alg in pub["SigningAlgorithms"], (
            f"the algorithm the signature was produced with must be advertised, "
            f"{sign_alg!r} not in {pub['SigningAlgorithms']!r}"
        )
        loaded = serialization.load_der_public_key(pub["PublicKey"])

        # Verify KMS's signature off AWS, independently of KMS Verify.
        assert _local_verify(loaded, signed["Signature"], message) is True, (
            f"the {sign_alg} signature KMS produced does not verify against the public key KMS "
            f"published for {key_arn!r} — the two halves are not a key pair"
        )

        # Proves the local verifier actually checks something.
        assert _local_verify(loaded, signed["Signature"], tampered) is False, (
            f"a one-bit message change must break local {sign_alg} verification — the local "
            f"verifier is not checking anything"
        )

        kms_verdict = kms.verify(
            KeyId=key_arn,
            Message=message,
            Signature=signed["Signature"],
            SigningAlgorithm=sign_alg,
        )
        assert kms_verdict["SignatureValid"] is True, (
            f"KMS Verify disagrees with the local verifier on its own signature: {kms_verdict!r}"
        )
        assert kms_verdict["SigningAlgorithm"] == sign_alg, kms_verdict

        if key_spec == "RSA_2048":
            assert isinstance(loaded, rsa.RSAPublicKey), type(loaded).__name__
            assert loaded.key_size == 2048, (
                f"the published RSA modulus is {loaded.key_size} bits, KeySpec says {key_spec!r}"
            )
            # Order is not guaranteed, so compare as a set.
            assert set(pub["SigningAlgorithms"]) == {
                "RSASSA_PKCS1_V1_5_SHA_256",
                "RSASSA_PKCS1_V1_5_SHA_384",
                "RSASSA_PKCS1_V1_5_SHA_512",
                "RSASSA_PSS_SHA_256",
                "RSASSA_PSS_SHA_384",
                "RSASSA_PSS_SHA_512",
            }, pub["SigningAlgorithms"]
        else:
            assert isinstance(loaded, ec.EllipticCurvePublicKey), type(loaded).__name__
            assert loaded.curve.name == "secp256r1", (
                f"ECC_NIST_P256 must publish a secp256r1 point, got {loaded.curve.name!r}"
            )
            assert set(pub["SigningAlgorithms"]) == {"ECDSA_SHA_256"}, pub["SigningAlgorithms"]

        verified.append(key_spec)

    assert verified == ["RSA_2048", "ECC_NIST_P256"], (
        f"both key specs must have been exercised, got {verified!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
