"""op-contract-import-key-pair."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-import-key-pair"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportKeyPair returns the MD5-of-SubjectPublicKeyInfo fingerprint for imported keys; a
    duplicate name is rejected without disturbing the original, and after removing the original
    the identical import succeeds again with the same fingerprint.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    ec2 = ctx.client("ec2")
    tag_spec = [{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}]

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    expected_fingerprint = _spki_md5_fingerprint(private_key.public_key())

    key_name = ctx.unique_name("sim2real-kp-")
    resp = ec2.import_key_pair(
        KeyName=key_name, PublicKeyMaterial=public_key_bytes, TagSpecifications=tag_spec
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=key_name))

    assert resp["KeyName"] == key_name
    assert resp.get("KeyPairId"), "ImportKeyPair returned no KeyPairId"
    assert resp.get("KeyFingerprint") == expected_fingerprint, (
        f"expected MD5-of-SubjectPublicKeyInfo fingerprint {expected_fingerprint!r} of the "
        f"imported public key, got {resp.get('KeyFingerprint')!r}"
    )

    described = ec2.describe_key_pairs(KeyNames=[key_name])["KeyPairs"]
    assert described and described[0]["KeyPairId"] == resp["KeyPairId"]
    assert described[0]["KeyFingerprint"] == expected_fingerprint, (
        "DescribeKeyPairs disagrees with ImportKeyPair's own fingerprint for the same key"
    )

    # break: re-importing under the same name is a duplicate, not an overwrite
    code, message = _client_error(
        lambda: ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=public_key_bytes)
    )
    assert code == "InvalidKeyPair.Duplicate", f"expected InvalidKeyPair.Duplicate, got {code!r}"
    expected_message = "The keypair already exists"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original key pair is untouched by the rejected duplicate
    still_there = ec2.describe_key_pairs(KeyNames=[key_name])["KeyPairs"]
    assert still_there and still_there[0]["KeyPairId"] == resp["KeyPairId"], (
        "the rejected duplicate import changed the original key pair's identity"
    )
    assert still_there[0]["KeyFingerprint"] == expected_fingerprint

    # restore: remove the original, then the identical import must succeed again
    ec2.delete_key_pair(KeyName=key_name)
    gone_code, gone_message = _client_error(lambda: ec2.describe_key_pairs(KeyNames=[key_name]))
    assert gone_code == "InvalidKeyPair.NotFound", f"expected key pair gone, got {gone_code!r}"
    expected_message = f"The key pair '{key_name}' does not exist"
    assert gone_message == expected_message, f"expected message {expected_message!r}, got {gone_message!r}"

    restored = ec2.import_key_pair(
        KeyName=key_name, PublicKeyMaterial=public_key_bytes, TagSpecifications=tag_spec
    )
    assert restored["KeyName"] == key_name
    assert restored["KeyPairId"] != resp["KeyPairId"], "a fresh import must mint a new KeyPairId"
    assert restored["KeyFingerprint"] == expected_fingerprint, (
        "the fingerprint of an imported key is a pure function of its public key bytes and must "
        "reproduce identically across delete-then-reimport"
    )


def _spki_md5_fingerprint(public_key) -> str:
    """ImportKeyPair's fingerprint is the MD5 digest of the public key's DER-encoded
    X.509 SubjectPublicKeyInfo, hex encoded with colon separators — distinct from
    CreateKeyPair's SHA-1 fingerprint of the generated private key. Neither the SSH wire-format
    blob nor a PKCS1 encoding matches what EC2 returns.
    """
    from cryptography.hazmat.primitives import serialization

    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.md5(der).digest()
    return ":".join(f"{b:02x}" for b in digest)


def _client_error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    else:
        raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
