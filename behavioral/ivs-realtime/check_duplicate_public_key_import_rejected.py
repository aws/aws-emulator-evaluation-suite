"""duplicate-public-key-import-rejected."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "duplicate-public-key-import-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



def _generate_valid_pem_public_key(ctx):
    """Return a real, valid PEM-encoded ECDSA (P-384) public key. IVS real-time requires
    ECDSA/secp384r1 keys for ImportPublicKey."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        key = ec.generate_private_key(ec.SECP384R1())
        pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("ascii")
    except ImportError:
        pass

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        pub_path = Path(tmp) / "pub.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", str(key_path)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-in", str(key_path), "-pubout", "-out", str(pub_path)],
            check=True, capture_output=True,
        )
        return pub_path.read_text()


def _public_key_names(ivs) -> set[str]:
    """Every public key name in the account, read across all pages."""
    return {
        k.get("name")
        for page in ivs.get_paginator("list_public_keys").paginate()
        for k in page.get("publicKeys", [])
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Importing the exact same public key material twice is rejected the second time."""
    ivs = ctx.client("ivs-realtime")
    pem = _generate_valid_pem_public_key(ctx)

    pk_tags = {"env": "sim2real", "owner": "behavioral"}

    # Positive control: the first import of this material succeeds.
    first = ivs.import_public_key(
        name=ctx.unique_name("sim2real-pk-"), publicKeyMaterial=pem, tags=pk_tags
    )["publicKey"]
    ctx.on_cleanup(lambda: ivs.delete_public_key(arn=first["arn"]))

    before = _public_key_names(ivs)
    assert first["name"] in before, (first["name"], before)

    dup_name = ctx.unique_name("sim2real-pk-")
    error = _client_error(
        lambda: ivs.import_public_key(name=dup_name, publicKeyMaterial=pem, tags=pk_tags)
    )
    assert error.get("Code") == "ConflictException", error
    assert error.get("Message") == (
        "A public-key resource already exists with the given publicKeyMaterial"
    ), error

    # The effect must be absent: no key under the duplicate's name, and the first still listed.
    after = _public_key_names(ivs)
    assert dup_name not in after and first["name"] in after, (dup_name, first["name"], after)

    # Positive control: a genuinely different key still imports fine, proving the
    # rejection is specific to duplicate material and not a blanket block on the API.
    distinct_pem = _generate_valid_pem_public_key(ctx)
    assert distinct_pem != pem, "generator returned the same key material twice"
    second = ivs.import_public_key(
        name=ctx.unique_name("sim2real-pk-"), publicKeyMaterial=distinct_pem, tags=pk_tags
    )["publicKey"]
    ctx.on_cleanup(lambda: ivs.delete_public_key(arn=second["arn"]))
    assert second["arn"] != first["arn"], (second["arn"], first["arn"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
