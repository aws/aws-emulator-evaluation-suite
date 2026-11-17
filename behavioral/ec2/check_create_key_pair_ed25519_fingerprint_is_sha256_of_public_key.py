"""create-key-pair-ed25519-fingerprint-is-sha256-of-public-key."""
from __future__ import annotations

import base64
import hashlib
import struct

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_ssh_private_key,
)

from behavioral_harness import tags

CHECK = "create-key-pair-ed25519-fingerprint-is-sha256-of-public-key"
GROUP = "key-pairs"
SERVICES = ["ec2"]


def _ssh_ed25519_fingerprint(raw_public_key: bytes) -> str:
    """Base64 SHA-256 digest of the SSH wire-format ed25519 public key blob."""
    algo = b"ssh-ed25519"
    blob = struct.pack(">I", len(algo)) + algo + struct.pack(">I", len(raw_public_key)) + raw_public_key
    return base64.b64encode(hashlib.sha256(blob).digest()).decode()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKeyPair KeyType=ed25519 returns a private key whose derived public key's SSH
    fingerprint equals KeyFingerprint, and DescribeKeyPairs reports the identical value.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-ec2-ed25519key-")

    created = ec2.create_key_pair(
        KeyName=name,
        KeyType="ed25519",
        TagSpecifications=[
            {"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "ed25519-fingerprint"}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=name))

    private_key = load_ssh_private_key(created["KeyMaterial"].encode(), password=None)
    raw_public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert len(raw_public_key) == 32, (
        f"an ed25519 public key is 32 raw bytes, the returned private key derives {len(raw_public_key)}"
    )

    expected_fingerprint = _ssh_ed25519_fingerprint(raw_public_key)
    assert created["KeyFingerprint"] == expected_fingerprint, (
        f"CreateKeyPair returned KeyFingerprint {created['KeyFingerprint']!r}, "
        f"expected the SHA-256 fingerprint {expected_fingerprint!r} of the returned private key's "
        f"own public key"
    )

    described = ec2.describe_key_pairs(KeyNames=[name], IncludePublicKey=True)["KeyPairs"][0]
    assert described["KeyFingerprint"] == created["KeyFingerprint"], (
        f"DescribeKeyPairs reports KeyFingerprint {described['KeyFingerprint']!r}, "
        f"CreateKeyPair returned {created['KeyFingerprint']!r}"
    )
    assert described["KeyType"] == "ed25519", f"DescribeKeyPairs reports KeyType {described['KeyType']!r}"

    algo, encoded_public_key = described["PublicKey"].split()[:2]
    assert algo == "ssh-ed25519", f"DescribeKeyPairs PublicKey algorithm is {algo!r}, expected 'ssh-ed25519'"
    described_blob = base64.b64decode(encoded_public_key)
    algo_len = struct.unpack(">I", described_blob[:4])[0]
    described_raw_public_key = described_blob[4 + algo_len + 4:]
    assert described_raw_public_key == raw_public_key, (
        "the public key DescribeKeyPairs reports does not match the public key derived from the "
        "private key CreateKeyPair returned"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
