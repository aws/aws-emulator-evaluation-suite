"""import-public-key-invalid-pem-rejected."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "import-public-key-invalid-pem-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _generate_valid_pem_public_key(ctx):
    """Return a real, valid PEM-encoded ECDSA (P-384) public key, or raise if we can't make
    one. IVS real-time requires ECDSA/secp384r1 keys for ImportPublicKey,
    not RSA -- an RSA key is syntactically PEM but is rejected by the service's own
    `publicKeyMaterial` constraint."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportPublicKey rejects material that does not match the PEM public-key pattern."""
    ivs = ctx.client("ivs-realtime")

    bad_name = ctx.unique_name("sim2real-pk-")
    code, message = _error(
        lambda: ivs.import_public_key(name=bad_name, publicKeyMaterial="not-a-pem-key")
    )
    assert code == "ValidationException", code
    expected_message = (
        "ImportPublicKey.publicKeyMaterial does not match the required pattern "
        "^.*-----BEGIN PUBLIC KEY-----\\r?\\n([a-zA-Z0-9+/=\\r\\n]+)\\r?\\n-----END PUBLIC KEY-----(\\r?\\n)?.*$"
    )
    assert message == expected_message, message

    # The rejected call must not have created a public key: an independent read taken right
    # after it lists no key under the rejected name.
    after_reject_names = _public_key_names(ivs)
    assert bad_name not in after_reject_names, (bad_name, after_reject_names)

    # Positive control: a well-formed PEM public key is accepted.
    pem = _generate_valid_pem_public_key(ctx)
    name = ctx.unique_name("sim2real-pk-")
    created = ivs.import_public_key(
        name=name, publicKeyMaterial=pem, tags={"sim2real": CHECK}
    )["publicKey"]
    ctx.on_cleanup(lambda: ivs.delete_public_key(arn=created["arn"]))
    assert created["name"] == name, (created.get("name"), name)

    after_create_names = _public_key_names(ivs)
    assert name in after_create_names and bad_name not in after_create_names, (
        name, bad_name, after_create_names
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
