"""import-playback-key-pair-wrong-key-type-rejected."""
from __future__ import annotations

import subprocess
import tempfile

from behavioral_harness import tags

CHECK = "import-playback-key-pair-wrong-key-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportPlaybackKeyPair with an RSA public key fails ValidationException with the exact message and creates no
    key pair, while an ECDSA P-384 key imports and reads back with the same fingerprint."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    ivs = ctx.client("ivs")

    rsa_pem = _generate_rsa_public_key_pem()
    bad_name = ctx.unique_name("sim2real-ivs-wrongtype-")
    error = _error(
        lambda: ivs.import_playback_key_pair(publicKeyMaterial=rsa_pem, name=bad_name)
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for an RSA public key, got {error['Code']!r}"
    )
    assert error["Message"] == (
        "Request member: publicKeyMaterial failed to satisfy the constraints: "
        "could not decode as a PEM file"
    ), repr(error["Message"])

    # Effect absent: no key pair was created for the rejected RSA material.
    assert bad_name not in _key_pair_names(ivs), (
        f"expected no key pair named {bad_name!r} after the rejected import"
    )

    # Positive control: a genuine ECDSA P-384 key is accepted normally.
    good_pem = _generate_ecdsa_p384_public_key_pem()
    good_name = ctx.unique_name("sim2real-ivs-righttype-")
    created = ivs.import_playback_key_pair(
        publicKeyMaterial=good_pem, name=good_name, tags={"purpose": "sim2real"}
    )["keyPair"]
    ctx.on_cleanup(lambda: ivs.delete_playback_key_pair(arn=created["arn"]))
    assert created["name"] == good_name, (
        f"expected created key pair name {good_name!r}, got {created['name']!r}"
    )

    # Terminal read: independent of the call that created it, at the destination.
    fetched = ivs.get_playback_key_pair(arn=created["arn"])["keyPair"]
    assert fetched["name"] == good_name, (
        f"expected fetched key pair name {good_name!r}, got {fetched['name']!r}"
    )
    assert fetched["fingerprint"] == created["fingerprint"], (
        f"expected fetched fingerprint {created['fingerprint']!r} to match the "
        f"import response, got {fetched['fingerprint']!r}"
    )


def _key_pair_names(ivs) -> set[str]:
    """Every playback key pair name in the account, read across all pages."""
    return {
        kp.get("name")
        for page in ivs.get_paginator("list_playback_key_pairs").paginate()
        for kp in page.get("keyPairs", [])
    }


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _generate_rsa_public_key_pem() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        private_path = f"{tmp}/key.pem"
        public_path = f"{tmp}/pub.pem"
        subprocess.run(
            ["openssl", "genrsa", "-out", private_path, "2048"], check=True, capture_output=True
        )
        subprocess.run(
            ["openssl", "rsa", "-in", private_path, "-pubout", "-out", public_path],
            check=True,
            capture_output=True,
        )
        with open(public_path) as fh:
            return fh.read()


def _generate_ecdsa_p384_public_key_pem() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        private_path = f"{tmp}/priv.pem"
        public_path = f"{tmp}/pub.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", private_path],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-in", private_path, "-pubout", "-out", public_path],
            check=True,
            capture_output=True,
        )
        with open(public_path) as fh:
            return fh.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
