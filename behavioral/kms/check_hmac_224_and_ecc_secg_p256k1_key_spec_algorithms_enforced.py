"""hmac-224-and-ecc-secg-p256k1-key-spec-algorithms-enforced."""
from __future__ import annotations

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from behavioral_harness import tags

CHECK = "hmac-224-and-ecc-secg-p256k1-key-spec-algorithms-enforced"
GROUP = "key_metadata"
SERVICES = ["kms"]

_WRONG_MAC_ALGORITHM = (
    "InvalidKeyUsageException",
    "Algorithm HMAC_SHA_256 is incompatible with key spec HMAC_224.",
)
_WRONG_SIGNING_ALGORITHM = (
    "InvalidKeyUsageException",
    "Algorithm ECDSA_SHA_384 is incompatible with key spec ECC_SECG_P256K1.",
)


def _teardown(undo, *not_found: str):
    """``undo()`` on cleanup; only the resource's own not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _call(fn):
    """fn()'s (Error.Code, Error.Message). An unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def expect_error(fn, code: str, message: str) -> None:
    got_code, got_message = _call(fn)
    assert got_code == code, f"expected code {code!r}, got {got_code!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """DescribeKey lists exactly HMAC_SHA_224 for an HMAC_224 key and ECDSA_SHA_256 for an
    ECC_SECG_P256K1 key, each proven by use, and each key refuses another algorithm of its own
    family (HMAC_SHA_256, ECDSA_SHA_384) with InvalidKeyUsageException and its exact message.
    """
    kms = ctx.client("kms")

    hmac_key = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-hmac224-"),
        KeyUsage="GENERATE_VERIFY_MAC",
        KeySpec="HMAC_224",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        _teardown(
            lambda: kms.schedule_key_deletion(KeyId=hmac_key, PendingWindowInDays=7),
            "NotFoundException",
        )
    )

    hmac_meta = kms.describe_key(KeyId=hmac_key)["KeyMetadata"]
    assert hmac_meta["KeySpec"] == "HMAC_224", hmac_meta["KeySpec"]
    assert hmac_meta["MacAlgorithms"] == ["HMAC_SHA_224"], hmac_meta["MacAlgorithms"]
    assert hmac_meta.get("SigningAlgorithms", []) == [], hmac_meta.get("SigningAlgorithms")
    assert hmac_meta.get("EncryptionAlgorithms", []) == [], hmac_meta.get("EncryptionAlgorithms")

    mac_message = b"sim2real-hmac-224-message"
    mac = kms.generate_mac(KeyId=hmac_key, Message=mac_message, MacAlgorithm="HMAC_SHA_224")["Mac"]
    assert len(mac) == 28, f"HMAC_SHA_224 must be a 28-byte MAC, got {len(mac)}"
    verified = kms.verify_mac(
        KeyId=hmac_key, Message=mac_message, MacAlgorithm="HMAC_SHA_224", Mac=mac
    )
    assert verified["MacValid"] is True, verified

    expect_error(
        lambda: kms.generate_mac(KeyId=hmac_key, Message=mac_message, MacAlgorithm="HMAC_SHA_256"),
        *_WRONG_MAC_ALGORITHM,
    )

    ec_key = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-ecsecgp256k1-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="ECC_SECG_P256K1",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        _teardown(
            lambda: kms.schedule_key_deletion(KeyId=ec_key, PendingWindowInDays=7),
            "NotFoundException",
        )
    )

    ec_meta = kms.describe_key(KeyId=ec_key)["KeyMetadata"]
    assert ec_meta["KeySpec"] == "ECC_SECG_P256K1", ec_meta["KeySpec"]
    assert ec_meta["SigningAlgorithms"] == ["ECDSA_SHA_256"], ec_meta["SigningAlgorithms"]
    assert ec_meta.get("EncryptionAlgorithms", []) == [], ec_meta.get("EncryptionAlgorithms")

    pub = kms.get_public_key(KeyId=ec_key)
    assert pub["KeySpec"] == "ECC_SECG_P256K1", pub["KeySpec"]
    assert pub["SigningAlgorithms"] == ["ECDSA_SHA_256"], pub["SigningAlgorithms"]
    assert pub.get("EncryptionAlgorithms", []) == [], pub.get("EncryptionAlgorithms")
    loaded = load_der_public_key(pub["PublicKey"])
    assert isinstance(loaded, ec.EllipticCurvePublicKey), type(loaded).__name__
    assert loaded.curve.name == "secp256k1", loaded.curve.name

    sign_message = b"sim2real-ecc-secg-p256k1-message"
    signature = kms.sign(
        KeyId=ec_key, Message=sign_message, MessageType="RAW", SigningAlgorithm="ECDSA_SHA_256"
    )["Signature"]
    loaded.verify(signature, sign_message, ec.ECDSA(hashes.SHA256()))

    expect_error(
        lambda: kms.sign(
            KeyId=ec_key, Message=sign_message, MessageType="RAW", SigningAlgorithm="ECDSA_SHA_384"
        ),
        *_WRONG_SIGNING_ALGORITHM,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
