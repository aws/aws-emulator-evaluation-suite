"""import-public-key-lifecycle."""
from __future__ import annotations

import os
import subprocess
import tempfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "import-public-key-lifecycle"
GROUP = "e2e"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportPublicKey returns the MD5 colon-hex fingerprint of the key's DER bytes; the key reads and lists until
    deleted, then a read and a delete fail ResourceNotFoundException with the exact message."""

    pem = _generate_ec_public_key_pem()

    ivsrt = ctx.client("ivs-realtime")
    name = ctx.unique_name("sim2real-ivsrt-pubkey-")
    created = ivsrt.import_public_key(
        name=name, publicKeyMaterial=pem, tags=_mgmt_tags()
    )["publicKey"]
    arn = created["arn"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            ivsrt.delete_public_key(arn=arn)

    ctx.on_cleanup(_cleanup)

    assert created["name"] == name
    expected_fingerprint = _md5_colon_hex(pem)
    assert created["fingerprint"] == expected_fingerprint, (
        f"expected md5 colon-hex of the DER public key {expected_fingerprint!r}, "
        f"got {created['fingerprint']!r}"
    )
    assert created["publicKeyMaterial"].strip() == pem.strip()

    fetched = ivsrt.get_public_key(arn=arn)["publicKey"]
    assert fetched["arn"] == arn
    assert fetched["fingerprint"] == created["fingerprint"]

    arns = {k["arn"] for k in ivsrt.list_public_keys()["publicKeys"]}
    assert arn in arns

    ivsrt.delete_public_key(arn=arn)
    state["deleted"] = True

    code, message = _error(lambda: ivsrt.get_public_key(arn=arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource: {arn} not found", message

    code, message = _error(lambda: ivsrt.delete_public_key(arn=arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource: {arn} not found", message


def _generate_ec_public_key_pem():
    # IVS real-time requires ECDSA/secp384r1 keys for ImportPublicKey (not P-256/RSA).
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "priv.pem")
        pub = os.path.join(d, "pub.pem")
        subprocess.run(
            ["openssl", "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", priv],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-in", priv, "-pubout", "-out", pub],
            check=True,
            capture_output=True,
        )
        with open(pub) as f:
            return f.read()


def _md5_colon_hex(pem: str) -> str:
    # The fingerprint is the MD5 digest of the key's DER bytes, formatted as lowercase
    # colon-separated hex.
    import base64
    import hashlib

    der = b"".join(
        base64.b64decode(line)
        for line in pem.strip().splitlines()
        if line and "-----" not in line
    )
    return ":".join(f"{b:02x}" for b in hashlib.md5(der).digest())


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


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
