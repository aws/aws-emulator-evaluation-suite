"""import-key-pair-accepts-an-rsa-3072-key-and-reports-its-fingerprint."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from behavioral_harness import tags

CHECK = "import-key-pair-accepts-an-rsa-3072-key-and-reports-its-fingerprint"
GROUP = "key-pair-import-formats"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportKeyPair accepts a 3072-bit RSA OpenSSH public key as an rsa key pair.

    Import and DescribeKeyPairs report the MD5 fingerprint of the key's SubjectPublicKeyInfo.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html
    """
    ec2 = ctx.client("ec2")
    public_key = rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key()
    material = public_key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = ":".join(f"{b:02x}" for b in hashlib.md5(der).digest())
    name = ctx.unique_name("sim2real-kp3072-")

    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=name))
    imported = ec2.import_key_pair(
        KeyName=name,
        PublicKeyMaterial=material,
        TagSpecifications=[
            {"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )
    assert imported["KeyName"] == name, f"ImportKeyPair named the pair {imported['KeyName']!r}"
    assert imported["KeyFingerprint"] == fingerprint, (
        f"ImportKeyPair reported fingerprint {imported['KeyFingerprint']!r} for the RSA-3072 key, "
        f"expected the MD5 of its SubjectPublicKeyInfo {fingerprint!r}"
    )

    described = ec2.describe_key_pairs(KeyNames=[name])["KeyPairs"]
    assert len(described) == 1, f"DescribeKeyPairs({name!r}) returned {described!r}"
    got = (described[0]["KeyPairId"], described[0]["KeyType"], described[0]["KeyFingerprint"])
    want = (imported["KeyPairId"], "rsa", fingerprint)
    assert got == want, (
        f"DescribeKeyPairs({name!r}) reports (KeyPairId, KeyType, KeyFingerprint) {got!r}, "
        f"expected {want!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
