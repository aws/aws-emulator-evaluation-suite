"""delete-public-key-not-found-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "delete-public-key-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePublicKey removes an existing key from the listing, and a repeat delete of it or a delete of a
    never-existing ARN fails ResourceNotFoundException with the exact message."""
    ivsrt = ctx.client("ivs-realtime")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: create a real key, and prove DeletePublicKey actually
    # deletes it -- an independent read shows it gone.
    pem = _generate_pem_public_key()
    created = ivsrt.import_public_key(
        name=ctx.unique_name("sim2real-pk-"),
        publicKeyMaterial=pem,
        tags={"sim2real-check": CHECK},
    )["publicKey"]
    real_arn = created["arn"]
    state = {"deleted": False}
    ctx.on_cleanup(lambda: state["deleted"] or ivsrt.delete_public_key(arn=real_arn))

    before = {k["arn"] for k in ivsrt.list_public_keys()["publicKeys"]}
    assert real_arn in before, (real_arn, before)

    ivsrt.delete_public_key(arn=real_arn)
    state["deleted"] = True

    after = {k["arn"] for k in ivsrt.list_public_keys()["publicKeys"]}
    assert real_arn not in after, (real_arn, after)

    # Negative, case 1: deleting the same, now-dead ARN again is rejected.
    code, message = _error(lambda: ivsrt.delete_public_key(arn=real_arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource: {real_arn} not found", message

    # Negative, case 2: an ARN that never referenced any key fails identically.
    bogus_arn = f"arn:aws:ivs:{ctx.region}:{account}:public-key/{uuid.uuid4().hex[:12]}"
    code, message = _error(lambda: ivsrt.delete_public_key(arn=bogus_arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource: {bogus_arn} not found", message


def _generate_pem_public_key() -> str:
    """Generate a fresh, valid PEM-encoded ECDSA (P-384) public key -- IVS
    real-time requires ECDSA/secp384r1 keys for ImportPublicKey, not RSA."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP384R1())
        pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("ascii")
    except ImportError:
        pass

    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    openssl = shutil.which("openssl")
    if not openssl:
        raise AssertionError(
            "neither the `cryptography` package nor the `openssl` CLI is available "
            "to generate a valid test EC public key"
        )
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        pub_path = Path(tmp) / "pub.pem"
        subprocess.run(
            [openssl, "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", str(key_path)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [openssl, "ec", "-in", str(key_path), "-pubout", "-out", str(pub_path)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return pub_path.read_text()


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts what AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
