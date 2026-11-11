"""import-playback-key-pair-duplicate-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "import-playback-key-pair-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _key_pair_names(ivs) -> set[str]:
    """Every playback key pair name in the account, read across all pages."""
    return {
        kp.get("name")
        for page in ivs.get_paginator("list_playback_key_pairs").paginate()
        for kp in page.get("keyPairs", [])
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second import of the same ECDSA P-384 key material fails ConflictException with the exact message and adds
    no key pair while the first stays readable, and an RSA key fails ValidationException with the exact message."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    key = ec.generate_private_key(ec.SECP384R1())
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    ivs = ctx.client("ivs")
    first_name = ctx.unique_name("sim2real-ivs-kp-first-")
    first = ivs.import_playback_key_pair(
        publicKeyMaterial=pem, name=first_name, tags={"purpose": "sim2real"}
    )["keyPair"]
    ctx.on_cleanup(lambda: ivs.delete_playback_key_pair(arn=first["arn"]))
    assert first["fingerprint"], f"expected a non-empty fingerprint, got {first['fingerprint']!r}"

    second_name = ctx.unique_name("sim2real-ivs-kp-second-")
    error = _error(
        lambda: ivs.import_playback_key_pair(publicKeyMaterial=pem, name=second_name)
    )
    assert error["Code"] == "ConflictException", f"expected ConflictException, got {error['Code']!r}"
    assert error["Message"] == (
        "A playback-key resource already exists with the given publicKeyMaterial"
    ), repr(error["Message"])

    # Effect absent: no second key pair was created for the duplicate material.
    assert second_name not in _key_pair_names(ivs), (
        f"expected no key pair named {second_name!r} after the rejected duplicate import"
    )

    # Positive control: the first import is fully readable with a matching fingerprint.
    fetched = ivs.get_playback_key_pair(arn=first["arn"])["keyPair"]
    assert fetched["fingerprint"] == first["fingerprint"], (
        f"expected fingerprint {first['fingerprint']!r}, got {fetched['fingerprint']!r}"
    )
    assert fetched["name"] == first_name, f"expected name {first_name!r}, got {fetched['name']!r}"

    # The docstring's RSA claim is a distinct assertion, not a restatement of the
    # duplicate-rejection contract above: assert it directly rather than let it stand
    # untested.
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    rsa_error = _error(
        lambda: ivs.import_playback_key_pair(
            publicKeyMaterial=rsa_pem, name=ctx.unique_name("sim2real-ivs-kp-rsa-")
        )
    )
    assert rsa_error["Code"] == "ValidationException", (
        f"expected ValidationException for an RSA key, got {rsa_error['Code']!r}"
    )
    assert rsa_error["Message"] == (
        "Request member: publicKeyMaterial failed to satisfy the constraints: "
        "could not decode as a PEM file"
    ), repr(rsa_error["Message"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
